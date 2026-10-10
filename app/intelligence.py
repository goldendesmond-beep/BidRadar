"""Deterministic bilingual matching. External text is data, never instructions."""
import re
import math
from collections import Counter

SECTORS = {
    'construction': ('المقاولات والإنشاءات', 'Construction', ['مقاول','إنشاء','انشاء','تشييد','تشطيب','بنية تحتية','construction','civil','contracting']),
    'hospitality': ('الفنادق والضيافة', 'Hospitality', ['فندق','فنادق','ضيافة','منتجع','hotel','hospitality','resort']),
    'manpower': ('توريد العمالة', 'Manpower', ['عمالة','العمال','قوى عاملة','manpower','staffing','outsourcing','recruitment']),
    'housekeeping': ('التدبير الفندقي', 'Housekeeping', ['تدبير فندقي','تنظيف غرف','housekeeping','room cleaning']),
    'cleaning': ('خدمات النظافة', 'Cleaning', ['نظافة','تنظيف','cleaning','janitorial']),
    'facilities': ('إدارة المرافق', 'Facilities', ['إدارة المرافق','ادارة المرافق','facility','facilities']),
    'maintenance': ('التشغيل والصيانة', 'Operation & maintenance', ['صيانة','تشغيل','maintenance','operation','hvac','mep','كهرباء','سباكة','تكييف']),
    'catering': ('الإعاشة', 'Catering', ['إعاشة','اعاشة','تغذية','مطابخ','catering','kitchen','food']),
    'security': ('الأمن والحراسة', 'Security', ['حراسة','أمن','امن','security','guard']),
    'laundry': ('المغاسل', 'Laundry', ['مغاسل','غسيل','laundry']),
    'logistics': ('النقل واللوجستيات', 'Logistics', ['نقل','لوجستي','logistics','transport','delivery']),
    'landscaping': ('الحدائق والنفايات', 'Landscaping & waste', ['حدائق','نفايات','landscaping','waste']),
    'supplies': ('التوريد والمستلزمات', 'Supplies', ['توريد','مستلزمات','معدات','supplies','equipment','supply']),
    'services': ('الخدمات الأخرى', 'Other services', ['خدمات','services']),
    'general_contracting': ('المقاولات العامة', 'General contracting', ['مقاولات عامة','مقاول عام','general contracting']),
    'mep': ('التكييف والكهرباء والسباكة', 'HVAC & MEP', ['hvac','mep','كهربائية','كهرباء','ميكانيكية','سباكة','تكييف']),
    'renovation': ('ترميم وتجديد المباني', 'Building renovation', ['ترميم','تجديد مباني','renovation','refurbishment']),
    'hotel_renovation': ('تجديد الفنادق', 'Hotel renovation', ['ترميم فندق','تجديد فندق','hotel renovation','hotel refurbishment']),
    'waste': ('إدارة النفايات', 'Waste management', ['نفايات','waste management']),
    'subcontracting': ('المقاولات من الباطن', 'Subcontracting', ['مقاول من الباطن','مقاولات من الباطن','subcontract']),
}
ALIASES = {k: ' '.join(v[2] + [v[1]]) for k, v in SECTORS.items()}

def normalize(text):
    text = str(text or '').lower()
    text = re.sub('[إأآ]', 'ا', text)
    text = re.sub('[ًٌٍَُِّْـ]', '', text)
    return text.replace('ى', 'ي')

def classify(text):
    text = normalize(text)
    hits = [key for key, val in SECTORS.items() if any(re.search(r'(?<!\w)'+re.escape(normalize(w))+r'(?!\w)',text) if w in ['العمال','أمن','امن','نقل','غسيل'] else normalize(w) in text for w in val[2])]
    return hits or ['services']

def tokens(text):
    return re.findall(r'[\w]{2,}', normalize(text))

def relevance(query, record):
    """Lexical engine with explicit bilingual sector expansion; no neural claim."""
    if not query:
        return 1.0
    text = normalize(' '.join(str(record.get(k) or '') for k in ['title','title_en','organization','organization_en','description','description_en','city','reference']))
    q = normalize(query)
    if q in text:
        return 1.0
    query_sectors = set(classify(q)) - {'services'}
    record_sectors = set(record.get('sectors', []))
    if query_sectors & record_sectors:
        return .75
    qt = set(tokens(q))
    return len(qt & set(tokens(text))) / max(1, len(qt))

def fit(record, company):
    if not company or not company.get('sectors'):
        return {'score': None, 'level':'unknown', 'reasons':[], 'limits':['حدد أنشطة الشركة لحساب توصية الملاءمة.']}
    matched = sorted(set(company.get('sectors', [])) & set(record.get('sectors', [])))
    rule_score = .7 if matched else .1
    reasons = ['تطابق النشاط: ' + ', '.join(SECTORS.get(k, (k,))[0] for k in matched)] if matched else []
    limits = [] if matched else ['لم يظهر تطابق واضح بين الأنشطة المعلنة ونشاط الشركة.']
    city = str(company.get('city','')).strip()
    targets=company.get('target_cities',[]) or ([city] if city else [])
    if any(normalize(c) in normalize(record.get('city')) for c in targets if c):
        rule_score += .2
        reasons.append('الموقع يطابق مدينة الشركة.')
    elif record.get('city') in ('السعودية','Saudi Arabia',None,''):
        rule_score += .05
        limits.append('موقع تنفيذ محدد غير معلن؛ يلزم مراجعة المصدر.')
    else:
        limits.append('قد يتطلب التنفيذ خارج مدينة الشركة.')
    lexical = relevance(company.get('services',''), record) if company.get('services') else (1 if matched else 0)
    score = round(min(1, .8 * rule_score + .2 * lexical) * 100)
    limits.append('لا توجد أدلة كافية للتحقق من التصنيف القانوني أو القدرة المالية أو عدد العمال المطلوب.')
    return {'score':score, 'level':'high' if score >= 70 else 'medium' if score >= 40 else 'low', 'rule_score':rule_score, 'lexical_score':lexical, 'reasons':reasons,'limits':limits}

def engines():
    return [
        {'id':'rules-v1','name':'Bilingual sector rules','status':'ACTIVE','cost':0,'scope':['classification','matching','deduplication']},
        {'id':'lexical-v1','name':'Bilingual lexical search','status':'ACTIVE','cost':0,'scope':['search','matching'],'note':'Lexical expansion, not neural semantic embeddings.'},
        {'id':'transformers','name':'Transformers.js / WebLLM / Ollama','status':'UNAVAILABLE','cost':0,'scope':[],'note':'No model weights installed or inference service verified.'},
    ]
