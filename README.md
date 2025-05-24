# IP Reputation Checker with VirusTotal

Bu script, IP adreslerinin VirusTotal üzerinden reputation kontrolünü yapmanızı sağlar.

## Özellikler

- IP adreslerini VirusTotal API üzerinden kontrol eder
- Zararlı/şüpheli IP'leri ayrı bir dosyaya kaydeder
- Bulunamayan IP'leri ayrı bir dosyaya kaydeder
- Her IP için detaylı JSON raporlarını saklar

## Kurulum

1. Python virtual environment oluşturun:
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac için
# veya
.\venv\Scripts\activate  # Windows için
```

2. Gerekli kütüphaneyi yükleyin:
```bash
pip install requests
```

3. VirusTotal API anahtarınızı alın:
   - https://www.virustotal.com/gui/ adresinden ücretsiz kayıt olun
   - API anahtarınızı profilinizden kopyalayın
   - `vt_ip_checker.py` dosyasındaki `API_KEY` değişkenini güncelleyin

## Kullanım

1. Kontrol edilecek IP adreslerini `ips.txt` dosyasına ekleyin (her satıra bir IP)

2. Scripti çalıştırın:
```bash
python vt_ip_checker.py
```

3. Sonuçları kontrol edin:
   - `malicious_ips.txt`: Zararlı/şüpheli bulunan IP'ler
   - `not_found_ips.txt`: VT veritabanında bulunmayan IP'ler
   - `responses/` klasörü: Her IP için detaylı JSON raporları

## Notlar

- VirusTotal Public API'nin rate limit sınırı vardır (dakikada 4 istek)
- Script bu nedenle her istek arasında 15 saniye bekler
- API anahtarınızı güvenli tutun ve public olarak paylaşmayın

## Lisans

MIT 