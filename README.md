# XSS Scanner Tool

XSS Scanner Tool, belirli URL'lerde ve bu URL'lerin parametrelerinde XSS (Cross-Site Scripting) güvenlik açıklarını tespit etmek için tasarlanmış çok iş parçacıklı bir araçtır. Araç, hem GET hem de DOM tabanlı XSS açıklarını tespit etmek için çeşitli testler yapar.

## Özellikler

- **URL Analizi:** Belirtilen URL'lerde XSS testleri gerçekleştirir.
- **XSS Testi:** Parametreler ve yüklerle XSS testleri yapar. 
- **DOM Tabanlı XSS:** HTML DOM analizine dayalı XSS taraması.
- **Yük Mutasyonu:** Farklı XSS yük varyasyonları deneyerek derinlemesine test sağlar.
- **Çok İş Parçacıklı:** Birden fazla iş parçacığı ile hızlı tarama sağlar.
- **Loglama:** Tarama sırasında detaylı loglar kaydedilir.

## Gereksinimler

Bu araç Python 3.6+ ile uyumludur. Aşağıdaki Python paketlerinin kurulmuş olması gereklidir:

- `requests`
- `termcolor`
- `beautifulsoup4`

## Kurulum

1. Gerekli Python paketlerini yükleyin:

   ```bash
   pip install requests termcolor beautifulsoup4
