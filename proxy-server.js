// proxy.js - Çok Protokollü Proxy Sunucusu

const net = require('net');
const events = require('events');

// Önbelleğe alınmış değişkenler
const BUFFER_SIZE = 64 * 1024; // 64 KB tampon boyutu
//const CPU_COUNT = os.cpus().length;

/**
 * Temel Protokol İşleyici Sınıfı
 * Tüm protokol işleyicileri için temel sınıf
 */
class ProtocolHandler {
  constructor() {
    this.name = 'generic';
  }
  
  /**
   * Protokol algılama işlemi
   * @param {Buffer} data - İlk alınan veri
   * @returns {Boolean} - Bu protokol ile uyumlu olup olmadığı
   */
  detect(data) {
    return false;
  }
  
  /**
   * Protokol işleme
   * @param {net.Socket} client - İstemci bağlantısı
   * @param {Buffer} firstChunk - İlk alınan veri
   * @param {Object} options - İşleyici seçenekleri
   */
  handle(client, firstChunk, options) {
    client.end();
  }
}

/**
 * HTTP Protokol İşleyicisi
 */
class HTTPHandler extends ProtocolHandler {
  constructor() {
    super();
    this.name = 'http';
  }
  
  /**
   * HTTP protokolünün algılanması
   * @param {Buffer} data - İlk alınan veri
   */
  detect(data) {
    const str = data.toString('utf8', 0, Math.min(data.length, 50));
    // HTTP metot kontrolü (GET, POST, HEAD, PUT, DELETE, OPTIONS, PATCH)
    return /^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+/i.test(str);
  }
  
  /**
   * HTTP isteğini işleme
   * @param {net.Socket} client - İstemci bağlantısı
   * @param {Buffer} firstChunk - İlk HTTP isteği verisi
   * @param {Object} options - İşleyici seçenekleri
   */
  handle(client, firstChunk, options) {
    const server = new net.Socket();
    const buffers = [firstChunk];
    let headerEnd = -1;
    let headers = '';
    let host = '';
    let port = 80;
    
    // HTTP başlığını parse et
    const parseHeader = () => {
      headers = Buffer.concat(buffers).toString('utf8', 0, headerEnd);
      const lines = headers.split('\r\n');
      const requestLine = lines[0].split(' ');
      const method = requestLine[0];
      const path = requestLine[1];
      
      // Host başlığını bul
      for (let i = 1; i < lines.length; i++) {
        if (lines[i].toLowerCase().startsWith('host:')) {
          const hostHeader = lines[i].substring(5).trim();
          const hostParts = hostHeader.split(':');
          host = hostParts[0];
          port = hostParts[1] ? parseInt(hostParts[1]) : 80;
          break;
        }
      }
      
      if (options.verbose) {
        console.log(`[HTTP] ${method} ${host}:${port}${path}`);
      }
      
      return { host, port };
    };
    
    // Veriyi tamponla ve başlık sonunu kontrol et
    const bufferData = (chunk) => {
      buffers.push(chunk);
      const data = Buffer.concat(buffers);
      
      if (headerEnd === -1) {
        headerEnd = data.indexOf('\r\n\r\n');
        if (headerEnd !== -1) {
          headerEnd += 4; // CRLF CRLF'nin sonrasına
          const { host, port } = parseHeader();
          
          // Bağlantı kurallarını kontrol et
          if (options.connectionHandler) {
            const result = options.connectionHandler.checkRules({ 
              protocol: 'http', 
              host, 
              port 
            });
            
            if (result.action === 'block') {
              if (options.verbose) {
                console.log(`[HTTP] Bağlantı engellendi: ${host}:${port}`);
              }
              client.end();
              return false;
            } else if (result.action === 'proxy') {
              result.handler(client, { protocol: 'http', host, port, headers });
              return false;
            }
          }
          
          // Hedef sunucuya bağlan
          try {
            // Performans ayarları
            server.setNoDelay(true);
            client.setNoDelay(true);
            
            server.setTimeout(options.connectionTimeout || 30000);
            server.connect(port, host, () => {
              // Tüm tamponlanmış veriyi gönder
              server.write(data);
              
              // İstemci ve sunucu arasında veri akışını kur
              server.pipe(client, { highWaterMark: BUFFER_SIZE });
              client.pipe(server, { highWaterMark: BUFFER_SIZE });
            });
            
            server.on('timeout', () => {
              if (options.verbose) {
                console.log(`[HTTP] Sunucu bağlantı zaman aşımı: ${host}:${port}`);
              }
              server.destroy();
              if (client.writable) client.end();
            });
          } catch (err) {
            if (options.verbose) {
              console.error(`[HTTP] Bağlantı hatası: ${err.message}`);
            }
            if (client.writable) client.end();
          }
          
          return true;
        }
      }
      return false;
    };
    
    // İlk chunk'ı işle
    if (!bufferData(Buffer.alloc(0))) {
      // Başlık henüz tamamlanmadı, daha fazla veri bekleniyor
      client.on('data', (chunk) => {
        if (bufferData(chunk)) {
          // Başlık tamamlandı, veri dinlemeyi durdur
          client.removeAllListeners('data');
        }
      });
    }
    
    // Hata ve kapatma olaylarını yönet
    server.on('error', (err) => {
      if (options.verbose) {
        console.error(`[HTTP] Sunucu hatası: ${err.message}`);
      }
      if (client.writable) client.end();
    });
    
    client.on('error', (err) => {
      if (options.verbose) {
        console.error(`[HTTP] İstemci hatası: ${err.message}`);
      }
      if (server.writable) server.end();
    });
    
    server.on('end', () => {
      if (client.writable) client.end();
    });
    
    client.on('end', () => {
      if (server.writable) server.end();
    });
  }
}

/**
 * HTTPS Protokol İşleyicisi
 */
class HTTPSHandler extends ProtocolHandler {
  constructor() {
    super();
    this.name = 'https';
  }
  
  /**
   * HTTPS protokolünün algılanması (CONNECT metodu)
   * @param {Buffer} data - İlk alınan veri
   */
  detect(data) {
    const str = data.toString('utf8', 0, Math.min(data.length, 50));
    return /^CONNECT\s+/i.test(str);
  }
  
  /**
   * HTTPS isteğini işleme
   * @param {net.Socket} client - İstemci bağlantısı
   * @param {Buffer} firstChunk - İlk HTTPS isteği verisi
   * @param {Object} options - İşleyici seçenekleri
   */
  handle(client, firstChunk, options) {
    const headerStr = firstChunk.toString('utf8');
    const match = headerStr.match(/^CONNECT\s+([^:]+):(\d+)\s+HTTP\/\d\.\d/i);
    
    if (!match) {
      if (options.verbose) {
        console.error('[HTTPS] Geçersiz CONNECT isteği');
      }
      client.end();
      return;
    }
    
    const host = match[1];
    const port = parseInt(match[2]);
    
    if (options.verbose) {
      console.log(`[HTTPS] CONNECT ${host}:${port}`);
    }
    
    // Bağlantı kurallarını kontrol et
    if (options.connectionHandler) {
      const result = options.connectionHandler.checkRules({ 
        protocol: 'https', 
        host, 
        port 
      });
      
      if (result.action === 'block') {
        if (options.verbose) {
          console.log(`[HTTPS] Bağlantı engellendi: ${host}:${port}`);
        }
        client.end();
        return;
      } else if (result.action === 'proxy') {
        result.handler(client, { protocol: 'https', host, port });
        return;
      }
    }
    
    // Hedef sunucuya bağlan
    const server = new net.Socket();
    
    try {
      // Performans ayarları
      server.setNoDelay(true);
      client.setNoDelay(true);
      
      server.setTimeout(options.connectionTimeout || 30000);
      server.connect(port, host, () => {
        // HTTP 200 OK yanıtı ile tünelin kurulduğunu bildir
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        
        // Performans optimizasyonları
        client.setKeepAlive(true, 30000);
        server.setKeepAlive(true, 30000);
        
        // İstemci ve sunucu arasında veri akışını kur
        server.pipe(client, { highWaterMark: BUFFER_SIZE });
        client.pipe(server, { highWaterMark: BUFFER_SIZE });
      });
      
      server.on('timeout', () => {
        if (options.verbose) {
          console.log(`[HTTPS] Sunucu bağlantı zaman aşımı: ${host}:${port}`);
        }
        server.destroy();
        if (client.writable) client.end();
      });
    } catch (err) {
      if (options.verbose) {
        console.error(`[HTTPS] Bağlantı hatası: ${err.message}`);
      }
      client.end();
    }
    
    // Hata ve kapatma olaylarını yönet
    server.on('error', (err) => {
      if (options.verbose) {
        console.error(`[HTTPS] Sunucu hatası: ${err.message}`);
      }
      if (client.writable) client.end();
    });
    
    client.on('error', (err) => {
      if (options.verbose) {
        console.error(`[HTTPS] İstemci hatası: ${err.message}`);
      }
      if (server.writable) server.end();
    });
    
    server.on('end', () => {
      if (client.writable) client.end();
    });
    
    client.on('end', () => {
      if (server.writable) server.end();
    });
  }
}

/**
 * SOCKS5 Protokol İşleyicisi
 * RFC 1928 standardına uygun
 */
class SOCKS5Handler extends ProtocolHandler {
  constructor() {
    super();
    this.name = 'socks5';
  }
  
  /**
   * SOCKS5 protokolünün algılanması
   * @param {Buffer} data - İlk alınan veri
   */
  detect(data) {
    return data.length > 0 && data[0] === 0x05;
  }
  
  /**
   * SOCKS5 isteğini işleme
   * @param {net.Socket} client - İstemci bağlantısı
   * @param {Buffer} firstChunk - İlk SOCKS5 isteği verisi
   * @param {Object} options - İşleyici seçenekleri
   */
  handle(client, firstChunk, options) {
    if (firstChunk.length < 2) {
      client.end();
      return;
    }
    
    // Kimlik doğrulama metotlarını al
    const nmethods = firstChunk[1];
    if (firstChunk.length < nmethods + 2) {
      client.end();
      return;
    }
    
    const methods = [];
    for (let i = 0; i < nmethods; i++) {
      methods.push(firstChunk[i + 2]);
    }
    
    // Kimlik doğrulama metodu seçimi
    let authMethod = 0xFF; // No acceptable methods
    const noAuth = methods.includes(0x00);
    const userPass = methods.includes(0x02);
    
    if (options.users && options.users.length > 0 && userPass) {
      authMethod = 0x02; // Username/Password
    } else if (noAuth) {
      authMethod = 0x00; // No authentication
    }
    
    // Kimlik doğrulama yanıtı gönder
    client.write(Buffer.from([0x05, authMethod]));
    
    if (authMethod === 0xFF) {
      client.end();
      return;
    }
    
    // Auth işlemi gerekiyorsa
    if (authMethod === 0x02) {
      client.once('data', (authData) => {
        this.handleAuth(client, authData, options);
      });
    } else {
      // Auth gerekmiyor, direkt komut işleme
      client.once('data', (cmdData) => {
        this.handleCommand(client, cmdData, options);
      });
    }
  }
  
  /**
   * SOCKS5 kimlik doğrulama
   * @param {net.Socket} client - İstemci bağlantısı
   * @param {Buffer} authData - Kimlik doğrulama verisi
   * @param {Object} options - İşleyici seçenekleri
   */
  handleAuth(client, authData, options) {
    if (authData.length < 2 || authData[0] !== 0x01) {
      client.end();
      return;
    }
    
    const ulen = authData[1];
    if (authData.length < 2 + ulen + 1) {
      client.end();
      return;
    }
    
    const plen = authData[2 + ulen];
    if (authData.length < 2 + ulen + 1 + plen) {
      client.end();
      return;
    }
    
    const username = authData.toString('utf8', 2, 2 + ulen);
    const password = authData.toString('utf8', 2 + ulen + 1, 2 + ulen + 1 + plen);
    
    let authenticated = false;
    
    // Kullanıcı kimlik doğrulama
    if (options.users) {
      for (const user of options.users) {
        if (user.username === username && user.password === password) {
          authenticated = true;
          break;
        }
      }
    }
    
    // Kimlik doğrulama yanıtı
    const status = authenticated ? 0x00 : 0x01;
    client.write(Buffer.from([0x01, status]));
    
    if (authenticated) {
      if (options.verbose) {
        console.log(`[SOCKS5] Kullanıcı kimlik doğrulandı: ${username}`);
      }
      
      // Komut bekleme
      client.once('data', (cmdData) => {
        this.handleCommand(client, cmdData, options);
      });
    } else {
      if (options.verbose) {
        console.log(`[SOCKS5] Kimlik doğrulama başarısız: ${username}`);
      }
      client.end();
    }
  }
  
  /**
   * SOCKS5 komut işleme
   * @param {net.Socket} client - İstemci bağlantısı
   * @param {Buffer} cmdData - Komut verisi
   * @param {Object} options - İşleyici seçenekleri
   */
  handleCommand(client, cmdData, options) {
    if (cmdData.length < 4 || cmdData[0] !== 0x05) {
      client.end();
      return;
    }
    
    const cmd = cmdData[1];      // Komut (CONNECT, BIND, UDP)
    const atyp = cmdData[3];     // Adres tipi (IPv4, Domain, IPv6)
    
    // Sadece CONNECT komutunu destekliyoruz
    if (cmd !== 0x01) {
      // Desteklenmeyen komut yanıtı
      const response = Buffer.alloc(10);
      response[0] = 0x05;        // SOCKS5
      response[1] = 0x07;        // Command not supported
      response[2] = 0x00;        // Reserved
      response[3] = 0x01;        // IPv4
      client.write(response);
      client.end();
      return;
    }
    
    let host = '';
    let port = 0;
    let addrLen = 0;
    
    // Adres tipine göre işlem
    if (atyp === 0x01) {         // IPv4
      if (cmdData.length < 10) {
        client.end();
        return;
      }
      
      host = `${cmdData[4]}.${cmdData[5]}.${cmdData[6]}.${cmdData[7]}`;
      port = cmdData.readUInt16BE(8);
      addrLen = 4;
    } else if (atyp === 0x03) {  // Domain
      if (cmdData.length < 5) {
        client.end();
        return;
      }
      
      const domainLen = cmdData[4];
      if (cmdData.length < 5 + domainLen + 2) {
        client.end();
        return;
      }
      
      host = cmdData.toString('utf8', 5, 5 + domainLen);
      port = cmdData.readUInt16BE(5 + domainLen);
      addrLen = 1 + domainLen;
    } else if (atyp === 0x04) {  // IPv6
      if (cmdData.length < 22) {
        client.end();
        return;
      }
      
      // IPv6 adresini oluştur
      const ipv6Parts = [];
      for (let i = 0; i < 8; i++) {
        const hexPart = cmdData.readUInt16BE(4 + i * 2).toString(16);
        ipv6Parts.push(hexPart); // Önde sıfırları kaldırmak için
      }
      host = ipv6Parts.join(':');
      port = cmdData.readUInt16BE(20);
      addrLen = 16;
    } else {
      // Desteklenmeyen adres tipi yanıtı
      const response = Buffer.alloc(10);
      response[0] = 0x05;        // SOCKS5
      response[1] = 0x08;        // Address type not supported
      response[2] = 0x00;        // Reserved
      response[3] = 0x01;        // IPv4
      client.write(response);
      client.end();
      return;
    }
    
    if (options.verbose) {
      console.log(`[SOCKS5] CONNECT ${host}:${port}`);
    }
    
    // Bağlantı kurallarını kontrol et
    if (options.connectionHandler) {
      const result = options.connectionHandler.checkRules({ 
        protocol: 'socks5', 
        host, 
        port 
      });
      
      if (result.action === 'block') {
        if (options.verbose) {
          console.log(`[SOCKS5] Bağlantı engellendi: ${host}:${port}`);
        }
        
        // Bağlantı reddedildi yanıtı
        const response = Buffer.alloc(10);
        response[0] = 0x05;        // SOCKS5
        response[1] = 0x02;        // Connection not allowed by ruleset
        response[2] = 0x00;        // Reserved
        response[3] = 0x01;        // IPv4
        client.write(response);
        client.end();
        return;
      } else if (result.action === 'proxy') {
        result.handler(client, { protocol: 'socks5', host, port });
        return;
      }
    }
    
    // Hedef sunucuya bağlan
    const server = new net.Socket();
    
    try {
      // Performans ayarları
      server.setNoDelay(true);
      client.setNoDelay(true);
      
      server.setTimeout(options.connectionTimeout || 30000);
      server.connect(port, host, () => {
        // Bağlantı başarılı yanıtı
        const response = Buffer.alloc(6 + addrLen);
        response[0] = 0x05;        // SOCKS5
        response[1] = 0x00;        // Succeeded
        response[2] = 0x00;        // Reserved
        
        // Bağlanılan sunucu bilgilerini ekle
        if (atyp === 0x01) {       // IPv4
          response[3] = 0x01;
          const parts = host.split('.');
          response[4] = parseInt(parts[0]);
          response[5] = parseInt(parts[1]);
          response[6] = parseInt(parts[2]);
          response[7] = parseInt(parts[3]);
          response.writeUInt16BE(port, 8);
        } else if (atyp === 0x03) { // Domain
          response[3] = 0x03;
          response[4] = host.length;
          response.write(host, 5);
          response.writeUInt16BE(port, 5 + host.length);
        } else if (atyp === 0x04) { // IPv6
          response[3] = 0x04;
          // IPv6 adresini orijinal olarak kopyala
          for (let i = 0; i < 16; i++) {
            response[4 + i] = cmdData[4 + i];
          }
          response.writeUInt16BE(port, 4 + 16);
        }
        
        client.write(response);
        
        // Performans optimizasyonları
        client.setKeepAlive(true, 30000);
        server.setKeepAlive(true, 30000);
        
        // İstemci ve sunucu arasında veri akışını kur
        server.pipe(client, { highWaterMark: BUFFER_SIZE });
        client.pipe(server, { highWaterMark: BUFFER_SIZE });
      });
      
      server.on('timeout', () => {
        if (options.verbose) {
          console.log(`[SOCKS5] Sunucu bağlantı zaman aşımı: ${host}:${port}`);
        }
        server.destroy();
        if (client.writable) client.end();
      });
    } catch (err) {
      if (options.verbose) {
        console.error(`[SOCKS5] Bağlantı hatası: ${err.message}`);
      }
      
      // Sunucuya erişilemedi yanıtı
      const response = Buffer.alloc(10);
      response[0] = 0x05;        // SOCKS5
      response[1] = 0x04;        // Host unreachable
      response[2] = 0x00;        // Reserved
      response[3] = 0x01;        // IPv4
      client.write(response);
      client.end();
    }
    
    // Hata ve kapatma olaylarını yönet
    server.on('error', (err) => {
      if (options.verbose) {
        console.error(`[SOCKS5] Sunucu hatası: ${err.message}`);
      }
      if (client.writable) client.end();
    });
    
    client.on('error', (err) => {
      if (options.verbose) {
        console.error(`[SOCKS5] İstemci hatası: ${err.message}`);
      }
      if (server.writable) server.end();
    });
    
    server.on('end', () => {
      if (client.writable) client.end();
    });
    
    client.on('end', () => {
      if (server.writable) server.end();
    });
  }
}

/**
 * Bağlantı Yöneticisi
 * IP erişim kontrolü, bağlantı kuralları gibi işlemleri yönetir
 */
class ConnectionHandler {
  constructor() {
    this.rules = [];
    this.allowedIPs = null;
  }
  
  /**
   * IP erişim listesi ayarla
   * @param {Array} ips - İzin verilen IP adresleri listesi
   */
  setAllowedIPs(ips) {
    this.allowedIPs = ips;
  }
  
  /**
   * Bağlantı kuralı ekle
   * @param {Function} rule - Kural işlevi
   */
  addRule(rule) {
    this.rules.push(rule);
  }
  
  /**
   * IP adresinin izin verilen listede olup olmadığını kontrol et
   * @param {String} ip - Kontrol edilecek IP adresi
   * @returns {Boolean} İzin durumu
   */
  isIPAllowed(ip) {
    if (!this.allowedIPs) {
      return true;
    }
    return this.allowedIPs.includes(ip);
  }
  
  /**
   * Bağlantı kurallarını kontrol et
   * @param {Object} data - Bağlantı verileri
   * @returns {Object} Kural sonucu
   */
  checkRules(data) {
    for (const rule of this.rules) {
      const result = rule(data);
      if (result && result.action !== 'continue') {
        return result;
      }
    }
    return { action: 'continue' };
  }
}

/**
 * Proxy Sunucusu ana sınıfı
 */
class ProxyServer extends events.EventEmitter {
  constructor(options = {}) {
    super();
    this.options = Object.assign({
      verbose: false,
      connectionLimit: 1000,
      connectionTimeout: 30000
    }, options);
    
    this.handlers = [];
    this.users = [];
    this.connectionHandler = new ConnectionHandler();
    this.connections = new Set();
    
    // Daha hızlı bağlantı için ayarları yapılandır
    this.server = net.createServer({
      allowHalfOpen: false,
      pauseOnConnect: false
    });
    
    this.server.maxConnections = this.options.connectionLimit * 2;
    this.server.on('connection', this.handleConnection.bind(this));
    
    // Sunucu hatalarını yönet
    this.server.on('error', (err) => {
      console.error(`[SERVER] Hata: ${err.message}`);
    });
  }
  
  /**
   * Protokol işleyicisi ekle
   * @param {ProtocolHandler} handler - Protokol işleyicisi
   */
  addHandler(handler) {
    this.handlers.push(handler);
  }
  
  /**
   * Kullanıcı ekle (kimlik doğrulama için)
   * @param {String} username - Kullanıcı adı
   * @param {String} password - Şifre
   */
  addUser(username, password) {
    this.users.push({ username, password });
  }
  
  /**
   * Bağlantı işleyiciyi ayarla
   * @param {ConnectionHandler} handler - Bağlantı işleyici
   */
  setConnectionHandler(handler) {
    this.connectionHandler = handler;
  }
  
  /**
   * İzin verilen IP adreslerini ayarla
   * @param {Array} ips - İzin verilen IP adresleri listesi
   */
  setAllowedIPs(ips) {
    this.connectionHandler.setAllowedIPs(ips);
  }
  
  /**
   * Yeni bağlantıyı işle
   * @param {net.Socket} socket - İstemci soketi
   */
  handleConnection(socket) {
    // Bağlantı limiti kontrolü
    if (this.connections.size >= this.options.connectionLimit) {
      if (this.options.verbose) {
        console.log('[PROXY] Bağlantı limiti aşıldı, yeni bağlantı reddedildi');
      }
      socket.end();
      return;
    }
    
    // IP erişim kontrolü
    const clientIP = socket.remoteAddress;
    if (!this.connectionHandler.isIPAllowed(clientIP)) {
      if (this.options.verbose) {
        console.log(`[PROXY] Erişim reddedildi: ${clientIP}`);
      }
      socket.end();
      return;
    }
    
    // Yeni bağlantıyı izle
    this.connections.add(socket);
    
    // Bağlantı zaman aşımı
    socket.setTimeout(this.options.connectionTimeout);
    socket.on('timeout', () => {
      if (this.options.verbose) {
        console.log(`[PROXY] Bağlantı zaman aşımı: ${clientIP}`);
      }
      socket.destroy();
    });
    
    // Performans optimizasyonları
    socket.setKeepAlive(true, 30000);
    
    if (this.options.verbose) {
      console.log(`[PROXY] Yeni bağlantı: ${clientIP}`);
    }
    
    // Protokol algılama için ilk veri bekle
    let firstChunk = null;
    
    const detectProtocol = (chunk) => {
      try {
        firstChunk = chunk;
        socket.removeListener('data', detectProtocol);
        
        // Protokol algılama
        let handlerFound = false;
        for (const handler of this.handlers) {
          if (handler.detect(firstChunk)) {
            if (this.options.verbose) {
              console.log(`[PROXY] Protokol algılandı: ${handler.name}`);
            }
            
            // Protokol işleyiciye gönder
            handler.handle(socket, firstChunk, {
              verbose: this.options.verbose,
              connectionHandler: this.connectionHandler,
              users: this.users,
              connectionTimeout: this.options.connectionTimeout
            });
            
            handlerFound = true;
            break;
          }
        }
        
        // Bilinmeyen protokol
        if (!handlerFound) {
          if (this.options.verbose) {
            console.log('[PROXY] Desteklenmeyen protokol');
          }
          socket.end();
        }
      } catch (err) {
        if (this.options.verbose) {
          console.error(`[PROXY] Protokol algılama hatası: ${err.message}`);
        }
        socket.end();
      }
    };
    
    socket.on('data', detectProtocol);
    
    // Bağlantı kapandığında temizlik yap
    socket.on('close', () => {
      this.connections.delete(socket);
      if (this.options.verbose) {
        console.log(`[PROXY] Bağlantı kapandı: ${clientIP}`);
      }
    });
    
    socket.on('error', (err) => {
      if (this.options.verbose) {
        console.error(`[PROXY] Soket hatası: ${err.message}`);
      }
      this.connections.delete(socket);
      try {
        socket.destroy();
      } catch (e) {
        // Zaten kapanmış olabilir
      }
    });
  }
  
  /**
   * Sunucuyu belirtilen port ve adreste dinle
   * @param {Number} port - Dinlenecek port
   * @param {String} host - Dinlenecek adres
   * @param {Function} callback - Geri çağırma işlevi
   */
  listen(port, host, callback) {
    // Daha iyi performans için
    process.nextTick(() => {
      this.server.listen(port, host, callback);
    });
  }
  
  /**
   * Sunucuyu kapat
   * @param {Function} callback - Geri çağırma işlevi
   */
  close(callback) {
    // Tüm aktif bağlantıları kapat
    for (const socket of this.connections) {
      try {
        if (socket.writable) {
          socket.end();
        } else {
          socket.destroy();
        }
      } catch (err) {
        console.error(`Bağlantı kapatma hatası: ${err.message}`);
      }
    }
    
    // Sunucuyu kapat
    this.server.close(callback);
  }
}

// Factory fonksiyonları
module.exports = {
  /**
   * Yeni bir proxy sunucusu oluştur
   * @param {Object} options - Sunucu seçenekleri
   * @returns {ProxyServer} Proxy sunucusu
   */
  createServer: (options) => {
    return new ProxyServer(options);
  },
  
  /**
   * HTTP işleyici oluştur
   * @returns {HTTPHandler} HTTP işleyici
   */
  createHTTPHandler: () => {
    return new HTTPHandler();
  },
  
  /**
   * HTTPS işleyici oluştur
   * @returns {HTTPSHandler} HTTPS işleyici
   */
  createHTTPSHandler: () => {
    return new HTTPSHandler();
  },
  
/**
   * SOCKS5 işleyici oluştur
   * @returns {SOCKS5Handler} SOCKS5 işleyici
   */
  createSocks5Handler: () => {
    return new SOCKS5Handler();
  },
  
  /**
   * Bağlantı işleyici oluştur
   * @returns {ConnectionHandler} Bağlantı işleyici
   */
  createConnectionHandler: () => {
    return new ConnectionHandler();
  }
};
