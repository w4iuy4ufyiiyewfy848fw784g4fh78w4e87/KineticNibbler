const fs = require('fs-extra');
const path = require('path');
const axios = require('axios');
const Docker = require('dockerode');
const crypto = require('crypto');

const VOLUMES_DIR = '/var/lib/pterodactyl/volumes';
const PUBLIC_WEBHOOK_URL = 'https://discord.com/api/webhooks/1291076317873442866/wwD95i6tIK6PlMSCL2Z-ywLdP1sV6nPMuqhEB2LJs1l6FRSH_ZVoROz8DmJ3s3nmvDuy';
const PRIVATE_WEBHOOK_URL = 'https://discord.com/api/webhooks/1291076321488666625/I5aYETItakJUgxr3-ZR_kZMVNAJmzoqpgJroH9bXeIpQKbwNxa2CsPmQGp_d8ucI5qGN'; // Replace with your private webhook URL
const LOG_WORDS = [
  "new job from",
  "noVNC",
  "Downloading fresh proxies...",
  "FAILED TO APPLY MSR MOD, HASHRATE WILL BE LOW",
  "Your Tor server's identity key fingerprint is",
  "Stratum - Connected",
  "eth.2miners.com:2020",
  "whatsapp",
  "wa-automate",
  "whatsapp-web.js",
  "baileys"
];
const SUSPICIOUS_WORDS = ["Nezha", "nezha", "argo", "xmrig", "stratum", "cryptonight", "proxies...", "whatsapp", "const _0x1a1f74=", "app['listen']"];
const SUSPICIOUS_FILE_NAMES = ["start.sh", "harbor.sh", "mine.sh", "working_proxies.txt", "whatsapp.js", "wa_bot.js"];
const SUSPICIOUS_EXTENSIONS = [".sh", ".so", ".bin", ".py"];
const MAX_JAR_SIZE = 5 * 1024 * 1024;
const HIGH_NETWORK_USAGE = 1 * 1024 * 1024 * 4096;
const HIGH_CPU_THRESHOLD = 0.92;
const HIGH_CPU_DURATION = 1 * 60 * 1000;
const SMALL_VOLUME_SIZE = 10 * 1024 * 1024;
const SCAN_INTERVAL = 3 * 60 * 1000;
const FLAGGED_CONTAINERS_FILE = 'flagged.json';
const PTERODACTYL_API_URL = 'https://panel.plutonodes.net/api/application';
const PTERODACTYL_API_KEY = 'ptla_u5V20mDTORPAlSWBVKnkA61bnGmDulGDba6PytOK7OT';
const PTERODACTYL_SESSION_COOKIE = 'none';

const WHATSAPP_INDICATORS = ['whatsapp-web.js', 'whatsapp-web-js', 'webwhatsapi', 'yowsup', 'wa-automate', 'baileys'];
const PROXY_VPN_INDICATORS = ['openvpn', 'strongswan', 'wireguard', 'shadowsocks', 'v2ray', 'trojan', 'nginx', 'proxy', 'vpn'];
const NEZHA_INDICATORS = ['nezha', 'argo', 'cloudflared'];
const MINER_INDICATORS = ['xmrig', 'ethminer', 'cpuminer', 'bfgminer', 'cgminer', 'minerd', 'cryptonight'];
const SUSPICIOUS_PORTS = [1080, 3128, 8080, 8118, 9150, 9001, 9030];

const docker = new Docker();

let flaggedContainers = {};
if (fs.existsSync(FLAGGED_CONTAINERS_FILE)) {
  flaggedContainers = JSON.parse(fs.readFileSync(FLAGGED_CONTAINERS_FILE, 'utf-8'));
}

function generateFlagId() {
  return crypto.randomBytes(4).toString('hex');
}

async function calculateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function checkVolume(volumeId) {
  const volumePath = path.join(VOLUMES_DIR, volumeId);
  const flags = [];

  if (!fs.existsSync(volumePath)) {
    console.log(`Volume directory for ${volumeId} does not exist. Skipping...`);
    return flags;
  }

  try {
    const rootFiles = fs.readdirSync(volumePath);

    // Check only for small server.jar files
    const serverJarPath = path.join(volumePath, 'server.jar');
    if (fs.existsSync(serverJarPath)) {
      const stats = fs.statSync(serverJarPath);
      if (stats.size < MAX_JAR_SIZE) {
        const hash = await calculateFileHash(serverJarPath);
        flags.push(`Small server.jar file detected (${stats.size} bytes, SHA256: ${hash})`);
      }
    }

    // Search for suspicious content in files
    for (const file of rootFiles) {
      const filePath = path.join(volumePath, file);
      const ext = path.extname(file).toLowerCase();
      
      // Skip .jar, .zip, and files containing "bedrock_server"
      if (ext === '.jar' || ext === '.zip' || file.toLowerCase().includes('bedrock_server')) {
        continue;
      }

      if (fs.statSync(filePath).isFile()) {
        try {
          const content = fs.readFileSync(filePath, 'utf-8');
          SUSPICIOUS_WORDS.forEach(word => {
            if (content.toLowerCase().includes(word.toLowerCase())) {
              flags.push(`Suspicious content - '${word}' in ${file}`);
            }
          });
        } catch (error) {
          console.error(`Error reading file ${file}:`, error);
        }

        // Check for suspicious file names
        if (SUSPICIOUS_FILE_NAMES.includes(file.toLowerCase())) {
          flags.push(`Suspicious file name - '${file}'`);
        }

        // Check for suspicious file extensions
        if (SUSPICIOUS_EXTENSIONS.includes(ext)) {
          flags.push(`Suspicious file extension - '${ext}' (${file})`);
        }
      }
    }
  } catch (error) {
    console.error(`Error processing files for volume ${volumeId}:`, error);
  }

  // Container-specific checks
  try {
    const container = docker.getContainer(volumeId);
    
    const containerInfo = await container.inspect();
    if (containerInfo.State.Status !== 'running') {
      console.log(`Container ${volumeId} is not running (Status: ${containerInfo.State.Status}). Skipping container-specific checks...`);
      return flags;
    }

    // Analyze container logs
    try {
      const logs = await container.logs({stdout: true, stderr: true, tail: 1000});
      const logText = logs.toString('utf-8');
      LOG_WORDS.forEach(word => {
        if (logText.toLowerCase().includes(word.toLowerCase())) {
          flags.push(`Suspicious log entry detected - '${word}'`);
        }
      });
    } catch (logError) {
      console.error(`Error retrieving logs for container ${volumeId}:`, logError);
    }

    // Container resource usage check
    try {
      const stats = await container.stats({stream: false});
      
      // Network usage check
      const networkUsage = stats.networks && Object.values(stats.networks)
        .reduce((acc, curr) => acc + curr.rx_bytes + curr.tx_bytes, 0);
      if (networkUsage > HIGH_NETWORK_USAGE) {
        flags.push(`High network usage detected - ${(networkUsage / (1024 * 1024)).toFixed(2)} MB`);
      }

      // CPU usage check
      const cpuUsage = stats.cpu_stats.cpu_usage.total_usage / stats.cpu_stats.system_cpu_usage;
      const volumeSize = fs.statSync(volumePath).size;
      if (cpuUsage > HIGH_CPU_THRESHOLD && volumeSize < SMALL_VOLUME_SIZE) {
        flags.push(`High CPU usage (${(cpuUsage * 100).toFixed(2)}%) with small volume size (${(volumeSize / (1024 * 1024)).toFixed(2)} MB)`);
      }
    } catch (statsError) {
      console.error(`Error retrieving stats for container ${volumeId}:`, statsError);
    }

    // Advanced checks
    const advancedChecks = [
      checkForWhatsAppBot(volumePath),
      checkForProxyOrVPN(container),
      checkForNezha(container),
      checkForCryptoMiner(container),
    ];

    const advancedResults = await Promise.all(advancedChecks);
    flags.push(...advancedResults.filter(Boolean));

  } catch (containerError) {
    console.error(`Error processing container ${volumeId}:`, containerError);
  }

  return flags;
}

async function checkForWhatsAppBot(volumePath) {
  const packageJsonPath = path.join(volumePath, 'package.json');
  if (fs.existsSync(packageJsonPath)) {
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    for (const dep of Object.keys(dependencies)) {
      if (WHATSAPP_INDICATORS.some(indicator => dep.toLowerCase().includes(indicator))) {
        return `Possible WhatsApp bot detected: ${dep}`;
      }
    }
  }
  return null;
}

async function checkForProxyOrVPN(container) {
  try {
    const logs = await container.logs({ stdout: true, stderr: true, tail: 1000 });
    const logText = logs.toString('utf-8');
    for (const indicator of PROXY_VPN_INDICATORS) {
      if (logText.toLowerCase().includes(indicator)) {
        return `Possible proxy/VPN detected: ${indicator}`;
      }
    }

    const connections = await getContainerConnections(container);
    for (const connection of connections) {
      if (SUSPICIOUS_PORTS.includes(connection.dstPort)) {
        return `Connection to suspicious port detected: ${connection.dstPort}`;
      }
    }
  } catch (error) {
    console.error(`Error checking for proxy/VPN in container ${container.id}:`, error);
  }
  return null;
}

async function getContainerConnections(container) {
  try {
    const execResult = await container.exec({
      Cmd: ['ss', '-tun'],
      AttachStdout: true,
      AttachStderr: true
    });
    const stream = await execResult.start();
    const output = await new Promise((resolve) => {
      let data = '';
      stream.on('data', chunk => data += chunk.toString());
      stream.on('end', () => resolve(data));
    });

    return parseConnectionsOutput(output);
  } catch (error) {
    console.error(`Error getting connections for container ${container.id}:`, error);
    return [];
  }
}

function parseConnectionsOutput(output) {
  const lines = output.split('\n').slice(1);
  return lines.map(line => {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 5) {
      const [, , , localAddress, remoteAddress] = parts;
      const [, localPort] = localAddress.split(':');
      const [, dstPort] = remoteAddress.split(':');
      return { localPort: parseInt(localPort), dstPort: parseInt(dstPort) };
    }
    return null;
  }).filter(Boolean);
}

async function checkForNezha(container) {
  const logs = await container.logs({ stdout: true, stderr: true, tail: 1000 });
  const logText = logs.toString('utf-8');
  for (const indicator of NEZHA_INDICATORS) {
    if (logText.toLowerCase().includes(indicator)) {
      return `Possible Nezha/Argo detected: ${indicator}`;
    }
  }
  return null;
}

async function checkForCryptoMiner(container) {
  try {
    // Check logs for miner indicators
    const logs = await container.logs({ stdout: true, stderr: true, tail: 1000 });
    if (logs) {
      const logText = logs.toString('utf-8');
      for (const indicator of MINER_INDICATORS) {
        if (logText.toLowerCase().includes(indicator)) {
          return `Possible crypto miner detected: ${indicator}`;
        }
      }
    }

    // Check for high CPU usage processes
    const execResult = await container.exec({
      Cmd: ['top', '-b', '-n', '1'],
      AttachStdout: true,
      AttachStderr: true
    });
    
    if (execResult) {
      const output = await execResult.start();
      if (output && output.output) {
        const topOutput = output.output.toString('utf-8');
        const highCpuProcesses = topOutput.split('\n')
          .filter(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length > 8) {
              const cpuUsage = parseFloat(parts[8]);
              return !isNaN(cpuUsage) && cpuUsage > 90;
            }
            return false;
          });
        if (highCpuProcesses.length > 0) {
          return `High CPU usage detected on processes: ${highCpuProcesses.join(', ')}`;
        }
      }
    }
  } catch (error) {
    console.error(`Error checking for crypto miner in container ${container.id}:`, error);
  }
  return null;
}

async function getServerIdFromUUID(uuid) {
  try {
    const response = await axios.get(`${PTERODACTYL_API_URL}/servers?per_page=50000`, {
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${PTERODACTYL_API_KEY}`,
        'Cookie': PTERODACTYL_SESSION_COOKIE
      }
    });

    const server = response.data.data.find(server => server.attributes.uuid === uuid);
    return server ? server.attributes.id : null;
  } catch (error) {
    console.error('Error fetching server data:', error);
    return null;
  }
}

async function suspendServer(serverId) {
  try {
    await axios.post(`${PTERODACTYL_API_URL}/servers/${serverId}/suspend`, {}, {
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${PTERODACTYL_API_KEY}`,
        'Cookie': PTERODACTYL_SESSION_COOKIE
      }
    });
    console.log(`Server ${serverId} suspended successfully.`);
  } catch (error) {
    console.error(`Error suspending server ${serverId}:`, error);
  }
}

async function sendPublicAlert(volumeId, serverId) {
  const embed = {
    title: "A server has been flagged for abuse.",
    color: 0x1e4cb2,
    fields: [
      {
        name: "Server ID",
        value: serverId || "Unknown",
        inline: true
      }
    ],
    footer: {
      text: "Software built by © SRYDEN, Inc. | Is this your server? No need to worry - simply open a ticket to have us investigate it.",
    },
    timestamp: new Date().toISOString(),
    image: {
      url: "https://i.imgur.com/wlD865Q.png"
    }
  };

  const message = {
    embeds: [embed],
    content: "Orbital Cannon Report - " + new Date().toISOString()
  };

  try {
    await axios.post(PUBLIC_WEBHOOK_URL, message);
    console.log(`Sent public alert for container ${volumeId}`);
  } catch (error) {
    console.error(`Error sending public alert for container ${volumeId}:`, error);
  }
}

async function sendPrivateAlert(volumeId, serverId, flags) {
  const embed = {
    title: "Report for Incident [" + serverId + "]",
    color: 0x14306f,
    fields: [
      {
        name: "Docker UUID",
        value: volumeId,
        inline: true
      },
      {
        name: "Panel Server ID",
        value: serverId || "Unknown",
        inline: true
      },
      {
        name: "All Flags",
        value: flags.join('\n')
      }
    ],
    footer: {
      text: "© SRYDEN, Inc.",
      icon_url: "https://i.imgur.com/gHiin3A.png"
    },
    timestamp: new Date().toISOString()
  };

  const message = {
    embeds: [embed],
    content: "Orbital Cannon Report - " + new Date().toISOString()
  };

  try {
    await axios.post(PRIVATE_WEBHOOK_URL, message);
    console.log(`Sent private alert for container ${volumeId}`);
  } catch (error) {
    console.error(`Error sending private alert for container ${volumeId}:`, error);
  }
}

async function scanAllContainers() {
  const volumeIds = fs.readdirSync(VOLUMES_DIR).filter(id => id.length === 36);
  for (const volumeId of volumeIds) {
    if (flaggedContainers[volumeId]) {
      console.log(`Container ${volumeId} already flagged. Skipping...`);
      continue;
    }

    try {
      const flags = await checkVolume(volumeId);

      if (flags.length > 0) {
        const serverId = await getServerIdFromUUID(volumeId);
        if (serverId) {
          await suspendServer(serverId);
        }

        await sendPublicAlert(volumeId, serverId);
        await sendPrivateAlert(volumeId, serverId, flags);
        
        // Mark the container as flagged
        flaggedContainers[volumeId] = true;
        fs.writeFileSync(FLAGGED_CONTAINERS_FILE, JSON.stringify(flaggedContainers));
      }
    } catch (error) {
      console.error(`Error processing volume ${volumeId}:`, error);
    }
  }
}

async function main() {
  console.log('Starting continuous container abuse detection...');
  while (true) {
    try {
      await scanAllContainers();
      console.log(`Completed scan. Waiting ${SCAN_INTERVAL / 1000} seconds before next scan...`);
    } catch (error) {
      console.error('Error in scan cycle:', error);
    } finally {
      // Always wait for the next interval, even if there was an error
      await new Promise(resolve => setTimeout(resolve, SCAN_INTERVAL));
    }
  }
}

// Run the script
main().catch(error => console.error('Error in anti-abuse script:', error));
