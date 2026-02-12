export type LookupType = 'ip' | 'domain' | 'hash';

export interface ProviderResponse {
  provider: string;
  confidence: string;
  status: 'success' | 'error' | 'no_key';
  data?: any;
  error?: string;
}

// IP validation regex - validates IPv4 addresses with proper octet ranges (0-255)
const IP_VALIDATION_REGEX = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

// VirusTotal - Very High Confidence
export async function lookupVirusTotal(
  type: LookupType,
  value: string,
  apiKey?: string
): Promise<ProviderResponse> {
  if (!apiKey) {
    return {
      provider: 'VirusTotal',
      confidence: 'very_high',
      status: 'no_key',
      error: 'API key not configured',
    };
  }

  try {
    let endpoint = '';
    if (type === 'ip') {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${value}`;
    } else if (type === 'domain') {
      endpoint = `https://www.virustotal.com/api/v3/domains/${value}`;
    } else if (type === 'hash') {
      endpoint = `https://www.virustotal.com/api/v3/files/${value}`;
    }

    const response = await fetch(endpoint, {
      headers: {
        'x-apikey': apiKey,
      },
    });

    if (!response.ok) {
      return {
        provider: 'VirusTotal',
        confidence: 'very_high',
        status: 'error',
        error: `HTTP ${response.status}`,
      };
    }

    const data = await response.json();
    return {
      provider: 'VirusTotal',
      confidence: 'very_high',
      status: 'success',
      data,
    };
  } catch (error: any) {
    return {
      provider: 'VirusTotal',
      confidence: 'very_high',
      status: 'error',
      error: error.message,
    };
  }
}

// ThreatFox - High Confidence
export async function lookupThreatFox(
  type: LookupType,
  value: string,
  apiKey?: string
): Promise<ProviderResponse> {
  try {
    // ThreatFox uses POST requests with JSON body
    const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query: 'search_ioc',
        search_term: value,
      }),
    });

    if (!response.ok) {
      return {
        provider: 'ThreatFox',
        confidence: 'high',
        status: 'error',
        error: `HTTP ${response.status}`,
      };
    }

    const data = await response.json();
    return {
      provider: 'ThreatFox',
      confidence: 'high',
      status: 'success',
      data,
    };
  } catch (error: any) {
    return {
      provider: 'ThreatFox',
      confidence: 'high',
      status: 'error',
      error: error.message,
    };
  }
}

// AlienVault OTX / LevelBlue - Medium Confidence
export async function lookupOTX(
  type: LookupType,
  value: string,
  apiKey?: string
): Promise<ProviderResponse> {
  if (!apiKey) {
    return {
      provider: 'OTX/LevelBlue',
      confidence: 'medium',
      status: 'no_key',
      error: 'API key not configured',
    };
  }

  try {
    let endpoint = '';
    if (type === 'ip') {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${value}/general`;
    } else if (type === 'domain') {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${value}/general`;
    } else if (type === 'hash') {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${value}/general`;
    }

    const response = await fetch(endpoint, {
      headers: {
        'X-OTX-API-KEY': apiKey,
      },
    });

    if (!response.ok) {
      return {
        provider: 'OTX/LevelBlue',
        confidence: 'medium',
        status: 'error',
        error: `HTTP ${response.status}`,
      };
    }

    const data = await response.json();
    return {
      provider: 'OTX/LevelBlue',
      confidence: 'medium',
      status: 'success',
      data,
    };
  } catch (error: any) {
    return {
      provider: 'OTX/LevelBlue',
      confidence: 'medium',
      status: 'error',
      error: error.message,
    };
  }
}

// AbuseIPDB - High Confidence, IP only
export async function lookupAbuseIPDB(
  type: LookupType,
  value: string,
  apiKey?: string,
  maxAgeInDays: number = 180
): Promise<ProviderResponse> {
  if (type !== 'ip') {
    return {
      provider: 'AbuseIPDB',
      confidence: 'high',
      status: 'error',
      error: 'Only IP addresses supported',
    };
  }

  if (!apiKey) {
    return {
      provider: 'AbuseIPDB',
      confidence: 'high',
      status: 'no_key',
      error: 'API key not configured',
    };
  }

  try {
    const url = new URL('https://api.abuseipdb.com/api/v2/check');
    url.searchParams.append('ipAddress', value);
    url.searchParams.append('maxAgeInDays', maxAgeInDays.toString());

    const response = await fetch(url.toString(), {
      headers: {
        Key: apiKey,
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      return {
        provider: 'AbuseIPDB',
        confidence: 'high',
        status: 'error',
        error: `HTTP ${response.status}`,
      };
    }

    const data = await response.json();
    return {
      provider: 'AbuseIPDB',
      confidence: 'high',
      status: 'success',
      data,
    };
  } catch (error: any) {
    return {
      provider: 'AbuseIPDB',
      confidence: 'high',
      status: 'error',
      error: error.message,
    };
  }
}

// IBM X-Force - Medium Confidence
export async function lookupIBMXForce(
  type: LookupType,
  value: string,
  apiKey?: string
): Promise<ProviderResponse> {
  if (!apiKey) {
    return {
      provider: 'IBM X-Force',
      confidence: 'medium',
      status: 'no_key',
      error: 'API key not configured',
    };
  }

  try {
    let endpoint = '';
    if (type === 'ip') {
      endpoint = `https://api.xforce.ibmcloud.com/ipr/${value}`;
    } else if (type === 'domain') {
      endpoint = `https://api.xforce.ibmcloud.com/url/${encodeURIComponent(value)}`;
    } else if (type === 'hash') {
      endpoint = `https://api.xforce.ibmcloud.com/malware/${value}`;
    }

    // IBM X-Force uses Basic authentication with API key and password in key
    // Expected format: "apikey:password" or just "apikey"
    const authHeader = `Basic ${btoa(apiKey)}`;

    const response = await fetch(endpoint, {
      headers: {
        Authorization: authHeader,
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      return {
        provider: 'IBM X-Force',
        confidence: 'medium',
        status: 'error',
        error: `HTTP ${response.status}`,
      };
    }

    const data = await response.json();
    return {
      provider: 'IBM X-Force',
      confidence: 'medium',
      status: 'success',
      data,
    };
  } catch (error: any) {
    return {
      provider: 'IBM X-Force',
      confidence: 'medium',
      status: 'error',
      error: error.message,
    };
  }
}

export async function lookupThreat(
  provider: string,
  type: LookupType,
  value: string,
  env: any,
  options?: any
): Promise<ProviderResponse> {
  switch (provider) {
    case 'virustotal':
      return lookupVirusTotal(type, value, env.VT_API_KEY);
    case 'threatfox':
      return lookupThreatFox(type, value, env.THREATFOX_API_KEY);
    case 'otx':
      return lookupOTX(type, value, env.OTX_API_KEY);
    case 'abuseipdb':
      return lookupAbuseIPDB(type, value, env.ABUSEIPDB_API_KEY, options?.maxAgeInDays);
    case 'ibm-xforce':
      return lookupIBMXForce(type, value, env.IBM_XF_API_KEY);
    default:
      return {
        provider,
        confidence: 'unknown',
        status: 'error',
        error: 'Unknown provider',
      };
  }
}

// Bulk lookup threat intelligence
export async function bulkLookupThreat(
  provider: string,
  type: LookupType,
  indicators: string[],
  env: any,
  options?: any
): Promise<Array<ProviderResponse & { indicator: string }>> {
  const results = await Promise.all(
    indicators.map(async (indicator) => {
      const result = await lookupThreat(provider, type, indicator.trim(), env, options);
      return { ...result, indicator: indicator.trim() };
    })
  );
  return results;
}

// Ping recon - resolve IP and get basic info
export async function pingRecon(target: string): Promise<any> {
  try {
    // Try to resolve the target to get IP information
    // Note: In Cloudflare Workers environment, we can't actually ping
    // but we can do DNS lookup and HTTP checks
    
    let resolvedIP = target;
    let hostname = target;
    
    // Check if target is already an IP or a domain
    const isIP = IP_VALIDATION_REGEX.test(target);
    
    if (!isIP) {
      // It's a domain, try to resolve it
      try {
        // Use a DNS-over-HTTPS service to resolve
        const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${target}&type=A`, {
          headers: { 'Accept': 'application/dns-json' }
        });
        
        if (dnsResponse.ok) {
          const dnsData: any = await dnsResponse.json();
          if (dnsData.Answer && dnsData.Answer.length > 0) {
            resolvedIP = dnsData.Answer[0].data;
          }
        }
      } catch (e) {
        // If DNS resolution fails, continue with domain as-is
      }
    }
    
    // Try to make an HTTP HEAD request to check connectivity
    let httpCheck = { reachable: false, statusCode: 0, responseTime: 0 };
    try {
      const startTime = Date.now();
      const response = await fetch(`https://${target}`, { 
        method: 'HEAD',
        signal: AbortSignal.timeout(5000)
      });
      const responseTime = Date.now() - startTime;
      httpCheck = {
        reachable: true,
        statusCode: response.status,
        responseTime
      };
    } catch (e) {
      // HTTP check failed, that's okay
    }
    
    return {
      status: 'success',
      target: target,
      resolvedIP: resolvedIP,
      isIP: isIP,
      hostname: isIP ? 'N/A' : target,
      httpCheck: httpCheck,
      timestamp: new Date().toISOString()
    };
  } catch (error: any) {
    return {
      status: 'error',
      target: target,
      error: error.message,
      timestamp: new Date().toISOString()
    };
  }
}

// Bulk WHOIS using ipinfo.io
export async function bulkWhois(
  targets: string[],
  apiKey?: string
): Promise<Array<any>> {
  const results = await Promise.all(
    targets.map(async (target) => {
      try {
        const trimmedTarget = target.trim();
        if (!trimmedTarget) {
          return {
            target: trimmedTarget,
            status: 'error',
            error: 'Empty target'
          };
        }
        
        // Build URL with or without API key
        const url = apiKey 
          ? `https://ipinfo.io/${trimmedTarget}?token=${apiKey}`
          : `https://ipinfo.io/${trimmedTarget}`;
        
        const response = await fetch(url, {
          headers: { 'Accept': 'application/json' }
        });
        
        if (!response.ok) {
          return {
            target: trimmedTarget,
            status: 'error',
            error: `HTTP ${response.status}`
          };
        }
        
        const data = await response.json();
        return {
          target: trimmedTarget,
          status: 'success',
          data: data
        };
      } catch (error: any) {
        return {
          target: target.trim(),
          status: 'error',
          error: error.message
        };
      }
    })
  );
  
  return results;
}
