
# SUNGATE TITAN API v3 - Fixed

## Sorun neydi?
Eski backend sadece TCP port açık mı diye bakıyordu. User/pass ne olursa olsun `ok:true` dönüyordu.

## Yeni backend ne yapıyor?
1. TCP connect
2. Server hello bekle
3. user/pass ile login packet gönder
4. Server card data gönderirse -> working
5. Kapatırsa / boş dönerse -> auth_failed

## Deploy (Render)
1. Bu klasörü GitHub'a at
2. Render > New Web Service > Repo seç
3. Build: pip install -r requirements.txt
4. Start: uvicorn main:app --host 0.0.0.0 --port $PORT
5. Deploy et, URL'i frontend'de BACKEND değişkenine yaz

## Test
curl -X POST https://your-url/check-cccam-sync -H "Content-Type: application/json" -d '{"lines":["C: host 12000 user pass"],"timeout":5}'
