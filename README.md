# Proxy Bridge

## Türkçe Açıklama

Proxy Bridge, birden fazla protokolü destekleyen yüksek performanslı bir proxy sunucusudur. HTTP, HTTPS ve SOCKS5 protokollerini otomatik olarak algılar ve yönlendirir. Güvenlik özellikleri, performans optimizasyonları ve genişletilebilir mimarisi ile ağ uygulamaları için güçlü bir çözüm sunar.

### Özellikler

- **Çoklu Protokol Desteği:** HTTP, HTTPS ve SOCKS5 protokollerini dinamik olarak algılar ve işler
- **Güvenlik Özellikleri:** IP beyaz listesi, SOCKS5 kimlik doğrulama ve özelleştirilebilir erişim kuralları
- **Performans Odaklı:** Tampon optimizasyonu, kalıcı bağlantılar ve düşük gecikme süresi için yapılandırma
- **Genişletilebilir Mimari:** Yeni protokol işleyicileri kolayca eklenebilir

## English Description

Proxy Bridge is a high-performance proxy server that supports multiple protocols. It automatically detects and routes HTTP, HTTPS, and SOCKS5 protocols. With security features, performance optimizations, and an extensible architecture, it provides a powerful solution for network applications.

### Features

- **Multi-Protocol Support:** Dynamically detects and processes HTTP, HTTPS, and SOCKS5 protocols
- **Security Features:** IP whitelisting, SOCKS5 authentication, and customizable access rules
- **Performance Focused:** Buffer optimization, persistent connections, and configurations for low latency
- **Extensible Architecture:** New protocol handlers can be easily added

## Implementation Details / Uygulama Detayları

### HTTP Handler / HTTP İşleyici

```javascript
// HTTP protokolü için istek yönetimi
// Request management for HTTP protocol
class HTTPHandler extends ProtocolHandler {
  detect(data) {
    // HTTP metot imzalarını kontrol eder (GET, POST, vb.)
    // Checks HTTP method signatures (GET, POST, etc.)
    return /^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+/i.test(str);
  }
  
  handle(client, firstChunk, options) {
    // HTTP başlıklarını parse eder ve hedef sunucuya bağlanır
    // Parses HTTP headers and connects to the target server
    // İstemci ve hedef sunucu arasında veri akışını kurar
    // Establishes data flow between client and target server
  }
}
```

### HTTPS Handler / HTTPS İşleyici

```javascript
// HTTPS (CONNECT metodu) için tünel yönetimi
// Tunnel management for HTTPS (CONNECT method)
class HTTPSHandler extends ProtocolHandler {
  detect(data) {
    // CONNECT metodu kontrolü
    // Checks for CONNECT method
    return /^CONNECT\s+/i.test(str);
  }
  
  handle(client, firstChunk, options) {
    // Hedef host ve port bilgilerini alır
    // Extracts target host and port information
    // Tünel bağlantısı kurar ve veri akışını sağlar
    // Establishes tunnel connection and enables data flow
  }
}
```

### SOCKS5 Handler / SOCKS5 İşleyici

```javascript
// SOCKS5 protokolü desteği (RFC 1928 standardı)
// SOCKS5 protocol support (RFC 1928 standard)
class SOCKS5Handler extends ProtocolHandler {
  detect(data) {
    // SOCKS5 protokol imzasını kontrol eder
    // Checks SOCKS5 protocol signature
    return data.length > 0 && data[0] === 0x05;
  }
  
  handle(client, firstChunk, options) {
    // SOCKS5 el sıkışma, kimlik doğrulama ve komut işleme
    // SOCKS5 handshake, authentication, and command processing
    // Desteklenen komutlar: CONNECT
    // Supported commands: CONNECT
    // IPv4, IPv6 ve domain adı desteği
    // Support for IPv4, IPv6, and domain names
  }
}
```

### Connection Handler / Bağlantı Yöneticisi

```javascript
// Bağlantı yönetimi ve erişim kontrolü
// Connection management and access control
class ConnectionHandler {
  // IP erişim kontrolü
  // IP access control
  isIPAllowed(ip) { /* ... */ }
  
  // Özelleştirilebilir bağlantı kuralları
  // Customizable connection rules
  checkRules(data) { /* ... */ }
  
  // Kural tabanlı bağlantı yönlendirme/engelleme
  // Rule-based connection routing/blocking
  addRule(rule) { /* ... */ }
}
```

### Proxy Server / Proxy Sunucusu

```javascript
// Ana proxy sunucu sınıfı
// Main proxy server class
class ProxyServer extends events.EventEmitter {
  constructor(options) {
    // Performans ayarları ve yapılandırma
    // Performance settings and configuration
  }
  
  // Protokol algılama ve istek yönlendirme
  // Protocol detection and request routing
  handleConnection(socket) { /* ... */ }
  
  // Sunucu başlatma ve durdurma
  // Server start and stop
  listen(port, host, callback) { /* ... */ }
  close(callback) { /* ... */ }
}
```

### Usage Example / Kullanım Örneği

```javascript
const proxy = require('./proxy-server');

// Proxy sunucusu oluşturma
// Create proxy server
const server = proxy.createServer({
  verbose: true,
  connectionLimit: 1000
});

// Protokol işleyicileri ekleme
// Add protocol handlers
server.addHandler(proxy.createHTTPHandler());
server.addHandler(proxy.createHTTPSHandler());
server.addHandler(proxy.createSocks5Handler());

// Sunucuyu başlatma
// Start server
server.listen(8080, '0.0.0.0', () => {
  console.log('Proxy Bridge running on port 8080');
});
``` 
