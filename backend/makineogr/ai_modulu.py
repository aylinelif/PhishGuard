import joblib
import numpy as np
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
import os

# --- MODELİ YÜKLEME ---
# Bu kod, model dosyasını otomatik olarak bu dosyanın yanında arar.
current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, "phishing_modeli.pkl")

try:
    model = joblib.load(model_path)
    model_yuklendi = True
except FileNotFoundError:
    model_yuklendi = False
    print(f"HATA: Model dosyası bulunamadı: {model_path}")


# --- YARDIMCI FONKSİYON: ÖZELLİK ÇIKARMA ---
def feature_extraction(url):
    features = []
    if not re.match(r"^https?", url):
        url = "http://" + url
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # 1. IP
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        features.append(-1)
    else:
        features.append(1)
    # 2. Uzunluk
    if len(url) < 54:
        features.append(1)
    elif 54 <= len(url) <= 75:
        features.append(0)
    else:
        features.append(-1)
    # 3. Kısaltma
    if re.search(r"bit\.ly|goo\.gl|tinyurl|is\.gd|cli\.gs", url):
        features.append(-1)
    else:
        features.append(1)
    # 4. @ İşareti
    if "@" in url:
        features.append(-1)
    else:
        features.append(1)
    # 5. Çift Slash
    if url.rfind("//") > 7:
        features.append(-1)
    else:
        features.append(1)
    # 6. Tire (-)
    if "-" in domain:
        features.append(-1)
    else:
        features.append(1)
    # 7. SSL
    if parsed_url.scheme == "https":
        features.append(1)
    else:
        features.append(-1)
    # 8. Domain Yaşı
    features.append(1)
    # 9. HTTPS Token
    if "https" in domain:
        features.append(-1)
    else:
        features.append(1)

    return np.array(features).reshape(1, -1)


# --- ANA FONKSİYON (Ekibin Çağıracağı Yer) ---
def tahmin_et(url):
    """
    Girdi: URL String
    Çıktı: Sözlük (Dictionary) -> {'durum': 1/-1, 'mesaj': '...', 'renk': '...'}
    """
    if not model_yuklendi:
        return {
            "durum": -1,
            "mesaj": "Sistem Hatası: Model Yüklenemedi",
            "renk": "#ff0000",
        }

    # 1. URL Düzeltme
    if not re.match(r"^https?", url):
        url_check = "http://" + url
    else:
        url_check = url
    domain = urlparse(url_check).netloc

    # 2. POLİS KONTROLÜ (Kurallar)
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        return {"durum": -1, "mesaj": "⚠️ ŞÜPHELİ IP ADRESİ TESPİTİ", "renk": "#ff4d4d"}

    if re.search(r"bit\.ly|goo\.gl|tinyurl|is\.gd|cli\.gs", url_check):
        return {
            "durum": -1,
            "mesaj": "⚠️ KISALTMA SERVİSİ (Link Gizlenmiş)",
            "renk": "#ff4d4d",
        }

    if "https" in domain:
        return {
            "durum": -1,
            "mesaj": "⚠️ ALDATMACA: URL içinde https kelimesi geçiyor",
            "renk": "#ff4d4d",
        }

    # 3. EKSTRA GÜVENLİK KONTROLLERİ (Model öncesi filtreler)
    
    # Uzun URL Kontrolü
    if len(url_check) > 75:
        return {"durum": -1, "mesaj": "⚠️ ÇOK UZUN URL: Genellikle kimlik avı saldırılarında kullanılır", "renk": "#ff4d4d"}
        
    # Kritik Kelimeler
    # Bu kelimeler domain içinde geçiyorsa ve bilinen güvenli bir site değilse
    supheli_kelimeler = [
        "login", "signin", "verify", "secure", "account", "update", "bank", "wallet", 
        "confirm", "bonus", "free", "gift", "service", "support", "auth", "pay"
    ]
    
    # Basit Whitelist (Güvenli Siteler)
    guvenli_siteler = [
        "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com", 
        "instagram.com", "twitter.com", "linkedin.com", "github.com", "turkiye.gov.tr",
        "paypal.com", "netflix.com", "adobe.com"
    ]
    
    # Yardımcı Fonk: Ana domaini al (örn: www.google.com -> google.com)
    def get_main_domain(d):
        parts = d.split('.')
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return d

    current_main_domain = get_main_domain(domain)

    # Whitelist Kontrolü
    is_safe_whitelisted = False
    for site in guvenli_siteler:
        if domain.endswith(site):
            is_safe_whitelisted = True
            break
            
    if is_safe_whitelisted:
        # Whitelisted (Tam eşleşme veya subdomain)
        # Ancak yine de model üzerinden geçirebiliriz veya direkt güvenli diyebiliriz.
        # Kullanıcı deneyimi için direkt güvenli diyelim, çünkü AI hata yapabilir.
        return {"durum": 1, "mesaj": "✅ GÜVENLİ SİTE (Doğrulanmış Kaynak)", "renk": "#28a745", "risk_puani": 1}
        
    else:
        # Whitelist DEĞİL. Olası Typosquatting (Taklit) Kontrolü
        # Güvenli sitelere ÇOK benziyor mu? (Örn: goossgle.com vs google.com)
        for site in guvenli_siteler:
            similarity = SequenceMatcher(None, current_main_domain, site).ratio()
            # Eşik değeri 0.8: Yüksek benzerlik ama eşit değil
            if similarity > 0.8:
                return {
                    "durum": -1, 
                    "mesaj": f"⚠️ KİMLİK AVI ŞÜPHESİ: Bu site '{site}' adresini taklit ediyor olabilir! ({current_main_domain})",
                    "renk": "#ff4d4d"
                }

        # Şüpheli Kelime Kontrolü
        found_keywords = [k for k in supheli_kelimeler if k in domain]
        if found_keywords:
            return {
                "durum": -1, 
                "mesaj": f"⚠️ ŞÜPHELİ İFADE TESPİTİ: Domain '{found_keywords[0]}' kelimesini içeriyor.",
                "renk": "#ff4d4d"
            }

    # 4. YAPAY ZEKA KONTROLÜ
    try:
        features = feature_extraction(url_check)
        prediction = model.predict(features)[0]
        
        # Olasılık tabanlı risk puanı hesaplama
        risk_puani = 0
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(features)[0]
            # Classes are [-1, 1], so index 1 is Safe (Class 1)
            # Safe Probability
            prob_safe = probs[1]
            # Risk is 1 - Safe
            # E.g. Safe 0.99 -> Risk 0.01 -> 1%
            # E.g. Safe 0.60 -> Risk 0.40 -> 40%
            risk_puani = int((1 - prob_safe) * 100)
        else:
            # Fallback for models without probability
            risk_puani = 10 if prediction == 1 else 90

        if prediction == 1:
            # Yapısal özelliklere göre ekstra ince ayar (heuristics)
            # Eğer model güvenli dese bile bazı özellikler "şüpheliye yakın" ise puanı artır
            
            # Örnek: URL biraz uzunsa risk puanını hafif artır
            if len(url_check) > 50:
                risk_puani += 5
            
            # Domain içinde tire varsa
            if "-" in domain:
                risk_puani += 3
                
            # Riski güvenli sınırında tut (Max 30, Min 1)
            risk_puani = max(1, min(30, risk_puani))
            
            return {
                "durum": 1, 
                "mesaj": "✅ GÜVENLİ SİTE (AI Analizi)", 
                "renk": "#28a745",
                "risk_puani": risk_puani
            }
        else:
            # Phishing ise risk puanı yüksek olmalı (Min 70)
            risk_puani = max(70, int((1 - prob_safe) * 100)) if hasattr(model, "predict_proba") else 95
            
            return {
                "durum": -1,
                "mesaj": "⚠️ YAPAY ZEKA UYARISI: Oltalama belirtileri tespit edildi!",
                "renk": "#ff4d4d",
                "risk_puani": risk_puani
            }

    except Exception as e:
        return {"durum": 0, "mesaj": f"Hata oluştu: {str(e)}", "renk": "#ffa500", "risk_puani": 50}
