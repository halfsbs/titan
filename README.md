# SUNGATE Backend - Ücretsiz Deploy Rehberi

Bu klasör Render / Koyeb / Railway için hazır.

## Dosyalar
- server_sungate_only.py -> senin backend
- requirements.txt -> gerekli paketler
- render.yaml -> Render otomatik tanıması için
- Procfile -> Railway/Koyeb için

## RENDER.COM (ÖNERİLEN - ÜCRETSİZ)
1. Bu klasörü Github'a yükle: github.com/new repo oluştur -> Upload
2. render.com -> Dashboard -> New + -> Web Service
3. Github repo'nu seç
4. Ayarlar:
   - Build Command: pip install -r requirements.txt
   - Start Command: uvicorn server_sungate_only:app --host 0.0.0.0 --port $PORT
5. Free plan seç -> Create Web Service
6. 2-3 dk sonra linkin hazır: https://sungate-api-xxxx.onrender.com

Test et: 
https://sungate-api-xxxx.onrender.com/  -> {"status":"ok"} görmen lazım

## KOYEB.COM (ALTERNATİF)
1. koyeb.com -> Create Service -> GitHub
2. Aynı repo'yu seç
3. Start command aynı
4. Deploy

## Frontend Bağlantısı
HTML/React dosyanda şu yeri değiştir:

const API_URL = "https://senin-render-linkin.onrender.com"

Eğer frontend'in hala https://your-api.com kullanıyorsa orayı değiştir.

## ÖNEMLİ NOT
Free plan'da 15dk istek gelmezse uyur. İlk check isteği 30sn gecikebilir, bu normal.
Job'lar RAM'de tutuluyor (cccam_jobs), sunucu uyuyunca silinir. Kalıcı olması için Redis gerekir ama şimdilik gerekmez.