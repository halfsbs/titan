// Frontend için bunu en üste ekle
const API_URL = localStorage.getItem('SUNGATE_API_URL') || 'https://SUNGATE-API-LINKINI-BURAYA-YAZ.onrender.com';

// Kullanım örneği:
fetch(`${API_URL}/check-cccam`, {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({lines: clineList, timeout: 5, delay: 1})
})