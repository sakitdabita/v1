export type LookupType = 'ip' | 'domain' | 'hash';

export interface ProviderResponse {
  provider: string;
  confidence: string;
  status: 'success' | 'error' | 'no_key';
  data?: any;
  error?: string;
}

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
  apiKey?: string
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
    url.searchParams.append('maxAgeInDays', '90');

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
  env: any
): Promise<ProviderResponse> {
  switch (provider) {
    case 'virustotal':
      return lookupVirusTotal(type, value, env.VT_API_KEY);
    case 'threatfox':
      return lookupThreatFox(type, value, env.THREATFOX_API_KEY);
    case 'otx':
      return lookupOTX(type, value, env.OTX_API_KEY);
    case 'abuseipdb':
      return lookupAbuseIPDB(type, value, env.ABUSEIPDB_API_KEY);
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
