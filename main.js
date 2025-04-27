const { createServer, createHTTPHandler, createHTTPSHandler, createSocks5Handler, createConnectionHandler } = require("./proxy-server");
const http = require("http");
const { exec } = require("child_process");
const dns = require("dns");

// DNS önbelleğe alma - bağlantıları hızlandırmak için
dns.setServers(["1.1.1.1", "8.8.8.8"]);

// Proxy aç
const enableProxy = async (ip, port) => {
  try {
    await new Promise((resolve, reject) => {
      exec(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f`, (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
    
    await new Promise((resolve, reject) => {
      exec(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /d "${ip}:${port}" /f`, (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
    
    // Proxy ayarlarını hemen uygula
    await new Promise((resolve, reject) => {
      exec(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyOverride /d "<local>" /f`, (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
    
    console.log(`Proxy Açıldı: ${ip}:${port}`);
  } catch (err) {
    console.error(`Proxy açılırken hata: ${err.message}`);
  }
};

// Proxy kapat
const disableProxy = async () => {
  try {
    await new Promise((resolve, reject) => {
      exec(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f`, (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
    console.log(`Proxy Kapatıldı`);
  } catch (err) {
    console.error(`Proxy kapatılırken hata: ${err.message}`);
  }
};

// Kullanım örneği
const server = createServer({ 
  verbose: false,
  connectionLimit: 2000,        // Daha fazla eşzamanlı bağlantı
  connectionTimeout: 30000      // Daha kısa zaman aşımı
});

// Protokol işleyicileri ekle
server.addHandler(createHTTPHandler());
server.addHandler(createHTTPSHandler());
server.addHandler(createSocks5Handler());

// Örnek kullanıcı ekle
//server.addUser("kullanici", "parola");

// Bağlantı yöneticisi oluştur
const connectionHandler = createConnectionHandler();

// Belirli bir alan adını engelleme
connectionHandler.addRule((data) => {
  if (data.host && data.host.includes("asyaanimeleri.vip")) {
    return { action: "block" };
  }
  return { action: "continue" };
});



// Domain listeleri
const discordDomains = [
  "dis.gd", "discord.co", "discord.com", "discord.design",
  "discord.dev", "discord.gg", "discord.gift", "discord.gifts",
  "discord.media", "discord.new", "discord.store", "discord.tools",
  "discordapp.com", "discordapp.net", "discordmerch.com",
  "discordpartygames.com", "discord-activities.com",
  "discordactivities.com", "discordsays.com", "discordstatus.com"
];

// API.ipify.org için yönlendirme kuralı
connectionHandler.addRule((data) => {



  const matched = discordDomains.some(domain =>
    data.host === domain || data.host.endsWith("." + domain)
  );

  if (data.host && matched) {
    return {
      action: "proxy",
      handler: (client, connData) => {
        try {
          // Dış proxy sunucusu bağlantı parametreleri
          const proxyOptions = {
            host: "45.141.150.49",
            port: 1080,
            method: "CONNECT",
            path: `${data.host}:${data.port}`,
            headers: {
              "Proxy-Authorization": "Basic " + Buffer.from("cemilkos:159951aa").toString("base64"),
              "Connection": "keep-alive"  // Keep-alive için
            },
            timeout: 8000,           // Daha kısa zaman aşımı
            agent: false             // Agent devre dışı - daha hızlı bağlantı
          };
          
          // Dış proxy sunucusuna bağlantı talebi
          const req = http.request(proxyOptions);
          
          req.on("connect", (res, socket) => {
            if (!client.writable) return;
            
            try {
              // Bağlantının başarıyla kurulduğunu bildir
              client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
              
              // Performans optimizasyonları
              socket.setNoDelay(true);      // Nagle algoritmasını devre dışı bırak
              client.setNoDelay(true);
              socket.setKeepAlive(true, 30000);  // Keep-alive etkinleştir
              
              // Veri akışını kur
              socket.pipe(client);
              client.pipe(socket);
              
              // Kapatma olaylarını yönet
              socket.on("end", () => {
                if (client.writable) client.end();
              });
              
              client.on("end", () => {
                if (socket.writable) socket.end();
              });
              
              // Hata yönetimi
              socket.on("error", (err) => {
                console.error(`Soket hatası: ${err.message}`);
                if (client.writable) client.end();
              });
            } catch (err) {
              console.error(`Bağlantı kurulurken hata: ${err.message}`);
              if (client.writable) client.end();
            }
          });
          
          // Hata yönetimi
          req.on("error", (err) => {
            console.error(`Proxy isteği hatası: ${err.message}`);
            if (client.writable) client.end();
          });
          
          // Zaman aşımı yönetimi
          req.on("timeout", () => {
            console.error("Proxy isteği zaman aşımına uğradı");
            req.destroy();
            if (client.writable) client.end();
          });
          
          req.end();
        } catch (err) {
          console.error(`Proxy handler hatası: ${err.message}`);
          if (client.writable) client.end();
        }
      }
    };
  }
  return { action: "continue" };
});

// Bağlantı yöneticisini ayarla
server.setConnectionHandler(connectionHandler);

// Sunucuyu başlat
const port = process.env.PORT || 8080;
const host = process.env.HOST || "0.0.0.0";

// Önce kapatarak başlatma - olası eski bağlantıları temizler
disableProxy().then(() => {
  server.listen(port, host, () => {
    console.log(`Çok protokollü proxy sunucusu ${host}:${port} adresinde çalışıyor`);
    console.log("Desteklenen protokoller: HTTP, HTTPS, SOCKS5");
    
    // Windows sisteminde proxy ayarlarını otomatik olarak yapılandır
    enableProxy(host == "0.0.0.0" ? "127.0.0.1" : host, port);
  });
});

// Güvenli kapatma
const shutdown = async () => {
  console.log("\nSunucu kapatılıyor...");
  
  // Sunucu kapatılırken proxy ayarlarını da sıfırla
  try {
    await disableProxy();
    server.close();
    setTimeout(() => {
      process.exit(0);
    }, 1000); // Tüm bağlantıların düzgün kapanması için zaman tanı
  } catch (err) {
    console.error(`Kapatma hatası: ${err.message}`);
    process.exit(1);
  }
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
