<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'

const currentTab = ref<'dashboard' | 'staged' | 'logs'>('dashboard')
const showHelpDialog = ref(false)
const showAuthError = ref(false)

const apiFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const response = await fetch(input, init)
  if (response.status === 401) {
    showAuthError.value = true
    throw new Error('Azure Login Required')
  }
  return response
}

const retryAuth = () => {
  showAuthError.value = false
  fetchProfile()
  fetchSubscriptions()
  if (vaultUris.value.length > 0) {
    fetchVaultKeys()
    fetchComparison()
  }
}

interface SecretValueStatus {
  value: string | null;
  status: string;
  identiconEmoji?: string;
  colorIndex?: number;
  isVulnerable?: boolean;
  vulnerableTooltip?: string;
  isStaged?: boolean;
}

interface SecretComparisonRow {
  secretName: string;
  vaultValues: Record<string, SecretValueStatus>;
  globalStatus: string;
}

interface DiscoveredVault {
  name: string;
  uri: string;
}

interface UserProfile {
  email: string;
  subscriptionName: string;
  initials: string;
}

interface SecuritySettings {
  minLength: number;
  ignoreValues: string[];
  includeKeyKeywords: string[];
}

const defaultSecuritySettings: SecuritySettings = {
  minLength: 15,
  ignoreValues: ['true', 'false', '0', '1', 'null', 'undefined', ''],
  includeKeyKeywords: ['salt', 'key', 'token', 'password', 'secret', 'pwd']
};

interface StagedChange {
  vaultUri: string;
  secretName: string;
  originalValue: string | null;
  newValue: string;
  type: 'CREATE' | 'UPDATE' | 'DELETE';
}
const stagedChanges = ref<StagedChange[]>([]);
const internalClipboard = ref<string | null>(null);

interface UiSettings {
  identiconsByRow: boolean;
  identiconsByCol: boolean;
  identicolorMode: 'ByRow' | 'None';
  statusFilter: string;
  securityByRow: boolean;
  securityByCol: boolean;
  nameFilter: string;
  resultLimit: number;
  showStagedOnly: boolean;
}

const defaultUiSettings: UiSettings = {
  identiconsByRow: true,
  identiconsByCol: true,
  identicolorMode: 'ByRow',
  statusFilter: 'Any',
  securityByRow: false,
  securityByCol: false,
  nameFilter: '',
  resultLimit: 50,
  showStagedOnly: false
};

const identiconEmojis = ['⚽', '🚗', '🚀', '🍎', '🍕', '💎', '🎲', '🎸', '🌈', '🔥', '🪐', '🦄', '🌵', '🍔', '🎨', '🧩', '🎈', '🔋', '🔮', '🧬'];

const hashString = (str: string) => {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
};

const profile = ref<UserProfile | null>(null)

const loadSharableConfig = () => {
  try {
    const params = new URLSearchParams(window.location.search);
    const s = params.get('s');
    if (s) {
      return JSON.parse(atob(s));
    }
  } catch (e) {
    console.warn('Failed to parse URL config', e);
  }
  return null;
};
const urlConfig = loadSharableConfig();

const syncUrl = () => {
  try {
    const payload = { u: uiSettings.value, v: vaultUris.value };
    const encoded = btoa(JSON.stringify(payload));
    const newUrl = new URL(window.location.href);
    newUrl.searchParams.set('s', encoded);
    window.history.replaceState({}, '', newUrl);
  } catch (e) { console.warn('Failed to sync URL', e); }
};

const loadSavedVaultUris = (): string[] => {
  if (urlConfig && urlConfig.v && Array.isArray(urlConfig.v)) {
    return urlConfig.v;
  }
  try {
    const saved = localStorage.getItem('savedVaultUris');
    return saved ? JSON.parse(saved) : [];
  } catch (e) { return []; }
};
const vaultUris = ref<string[]>(loadSavedVaultUris())
watch(vaultUris, (newVal) => {
  localStorage.setItem('savedVaultUris', JSON.stringify(newVal));
  syncUrl();
}, { deep: true });
const availableVaults = ref<DiscoveredVault[]>([])
const loadingVaults = ref(false)
const results = computed<SecretComparisonRow[]>(() => {
  const filtered = filteredNames.value;
  
  return filtered.slice(0, uiSettings.value.resultLimit > 0 ? uiSettings.value.resultLimit : undefined).map(name => {
    const row: SecretComparisonRow = {
      secretName: name,
      vaultValues: {},
      globalStatus: 'Missing'
    };
    
    vaultUris.value.forEach(uri => {
      const knownNamesForVault = knownSecretNames.value[uri] || [];
      let baseStatus: SecretValueStatus;
      
      if (!knownNamesForVault.includes(name)) {
        baseStatus = { status: 'Missing', value: null, colorIndex: 0, isVulnerable: false };
      } else {
        const d = vaultData.value[uri]?.[name];
        baseStatus = d ? { ...d, colorIndex: 0, isVulnerable: false } : { status: 'Not Retrieved', value: null, colorIndex: 0, isVulnerable: false };
      }

      const staged = stagedChanges.value.find(s => s.vaultUri === uri && s.secretName === name);
      if (staged) {
        baseStatus.value = staged.newValue;
        baseStatus.status = 'Present';
        baseStatus.isStaged = true;
      }
      
      row.vaultValues[uri] = baseStatus;
      
      // Calculate identicons based on dimension logic
      const valStr = row.vaultValues[uri].value as string | null;
      const valLower = valStr?.toLowerCase();
      if (valLower && !securitySettings.value.ignoreValues.includes(valLower)) {
        let hashKey = '';
        let isDuplicated = false;

        if (uiSettings.value.identiconsByRow && uiSettings.value.identiconsByCol) {
          hashKey = valLower;
          isDuplicated = globalUsageCount.value.get(valLower)! > 1;
        } else if (uiSettings.value.identiconsByRow) {
          hashKey = name + valLower;
          isDuplicated = rowUsageCount.value.get(hashKey)! > 1;
        } else if (uiSettings.value.identiconsByCol) {
          hashKey = uri + valLower;
          isDuplicated = colUsageCount.value.get(hashKey)! > 1;
        }

        if (isDuplicated) {
          const hash = hashString(hashKey);
          row.vaultValues[uri].identiconEmoji = identiconEmojis[hash % identiconEmojis.length];
        }
      }

      // Check vulnerability
      if (valLower && vulnerableValuesMap.value.has(valLower)) {
        row.vaultValues[uri].isVulnerable = true;
        const usages = vulnerableValuesMap.value.get(valLower);
        row.vaultValues[uri].vulnerableTooltip = `Reused in ${usages?.length} secrets: ${usages?.join(', ')}. Click to highlight occurrences.`;
      }
    });

    // Compute color index based on distinct values
    const distinctValues = Object.values(row.vaultValues)
      .filter(v => v.status !== 'Missing' && v.status !== 'Not Retrieved' && v.status !== 'Error' && v.status !== 'Loading' && v.value !== null)
      .map(v => v.value!.toLowerCase())
      .filter((v, i, a) => a.indexOf(v) === i);

    Object.values(row.vaultValues).forEach(status => {
      if (status.status !== 'Present' || status.value === null) {
        status.colorIndex = 0;
      } else {
        status.colorIndex = distinctValues.indexOf(status.value.toLowerCase()) + 1;
      }
    });

    // Compute global status
    const statuses = Object.values(row.vaultValues);
    if (statuses.some(s => s.status === 'Missing')) {
      row.globalStatus = 'Missing';
    } else if (statuses.some(s => s.status !== 'Present' && s.status !== 'Match' && s.status !== 'Mismatch')) {
      row.globalStatus = 'Incomplete';
    } else {
      const firstValue = statuses.find(s => s.status === 'Present')?.value?.toLowerCase();
      if (firstValue !== undefined && statuses.every(s => s.value?.toLowerCase() === firstValue)) {
        row.globalStatus = 'Match';
      } else {
        row.globalStatus = 'Mismatch';
      }
    }

    return row;
  });
})

const loadUiSettings = (): UiSettings => {
  let base = { ...defaultUiSettings };
  try {
    const stored = localStorage.getItem('uiSettings');
    if (stored) base = { ...base, ...JSON.parse(stored) };
  } catch (e) { console.error('Failed to parse UI settings', e); }
  
  if (urlConfig && urlConfig.u) {
    base = { ...base, ...urlConfig.u };
  }
  return base;
};
const uiSettings = ref<UiSettings>(loadUiSettings());
watch(uiSettings, (newVal) => {
  localStorage.setItem('uiSettings', JSON.stringify(newVal));
  syncUrl();
}, { deep: true });

const loading = ref(false)
const visibleSecrets = ref(new Set<string>())

const highlightedValue = ref<string | null>(null)
const toggleHighlight = (val: string | null | undefined) => {
  if (!val) return
  highlightedValue.value = highlightedValue.value === val ? null : val
}

const loadKnownSecretNames = (): Record<string, string[]> => {
  try {
    const saved = localStorage.getItem('savedKnownSecretNames');
    if (saved) {
      const parsed = JSON.parse(saved);
      for (const uri in parsed) {
        parsed[uri] = parsed[uri].map((n: string) => n.toUpperCase());
      }
      return parsed;
    }
  } catch (e) { return {}; }
  return {};
};
const knownSecretNames = ref<Record<string, string[]>>(loadKnownSecretNames())
watch(knownSecretNames, (newVal) => {
  localStorage.setItem('savedKnownSecretNames', JSON.stringify(newVal));
}, { deep: true });
const vaultData = ref<Record<string, Record<string, SecretValueStatus & { colorIndex?: number }>>>({})

const loadSecuritySettings = (): SecuritySettings => {
  try {
    const stored = localStorage.getItem('securitySettings');
    if (stored) return JSON.parse(stored);
  } catch (e) { console.error('Failed to parse security settings', e); }
  return defaultSecuritySettings;
};
const securitySettings = ref<SecuritySettings>(loadSecuritySettings());
watch(securitySettings, (newVal) => {
  localStorage.setItem('securitySettings', JSON.stringify(newVal));
}, { deep: true });

const vulnerableValuesMap = computed(() => {
  const valueMap = new Map<string, Set<string>>(); // value -> Set of secretNames
  
  // Build value map
  for (const uri of Object.keys(vaultData.value)) {
    for (const [name, status] of Object.entries(vaultData.value[uri])) {
      if (status.status === 'Present' && status.value) {
        const valLower = status.value.toLowerCase();
        if (!valueMap.has(valLower)) valueMap.set(valLower, new Set());
        valueMap.get(valLower)!.add(name);
      }
    }
  }

  const vulnerable = new Map<string, string[]>();
  const settings = securitySettings.value;
  
  for (const [val, names] of valueMap.entries()) {
    if (names.size > 1) { // It's reused
      if (settings.ignoreValues.includes(val)) continue;

      const hasCriticalName = Array.from(names).some(name => {
        const lowerName = name.toLowerCase();
        return settings.includeKeyKeywords.some(kw => lowerName.includes(kw));
      });

      if (val.length >= settings.minLength || hasCriticalName) {
        vulnerable.set(val, Array.from(names));
      }
    }
  }
  return vulnerable;
});

const globalUsageCount = computed(() => {
  const counts = new Map<string, number>();
  for (const uri of Object.keys(vaultData.value)) {
    for (const status of Object.values(vaultData.value[uri])) {
      if (status.status === 'Present' && status.value) {
        const val = status.value.toLowerCase();
        counts.set(val, (counts.get(val) || 0) + 1);
      }
    }
  }
  return counts;
});

const rowUsageCount = computed(() => {
  const counts = new Map<string, number>();
  for (const uri of Object.keys(vaultData.value)) {
    for (const [name, status] of Object.entries(vaultData.value[uri])) {
      if (status.status === 'Present' && status.value) {
        const key = name + status.value.toLowerCase();
        counts.set(key, (counts.get(key) || 0) + 1);
      }
    }
  }
  return counts;
});

const colUsageCount = computed(() => {
  const counts = new Map<string, number>();
  for (const uri of Object.keys(vaultData.value)) {
    for (const status of Object.values(vaultData.value[uri])) {
      if (status.status === 'Present' && status.value) {
        const key = uri + status.value.toLowerCase();
        counts.set(key, (counts.get(key) || 0) + 1);
      }
    }
  }
  return counts;
});

const subscriptions = ref<Array<{id: string, name: string}>>([])
const selectedSubscriptionId = ref(localStorage.getItem('selectedSub') || '')

watch(selectedSubscriptionId, (newId) => {
  localStorage.setItem('selectedSub', newId)
  availableVaults.value = [] // Clear old vault options since the sub changed
})

const fetchComparison = async () => {
  if (vaultUris.value.length === 0) return
  
  loading.value = true
  try {
    const tasks = vaultUris.value.map(uri => fetchValuesForVault(uri))
    await Promise.all(tasks)
  } catch (error) {
    console.error('Error fetching comparison:', error)
    alert('Failed to fetch comparison data. Please try again.')
  } finally {
    loading.value = false
  }
}

const refetchNames = async () => {
  if (vaultUris.value.length === 0) return;
  loading.value = true;
  try {
    const response = await apiFetch('/api/vaults/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(vaultUris.value)
    });
    if (!response.ok) throw new Error('Failed to fetch keys');
    const data = await response.json();
    
    for (const [uri, names] of Object.entries(data)) {
      knownSecretNames.value[uri] = (names as string[]).map(n => n.toUpperCase());
    }
  } catch (error) {
    console.error('Error fetching names:', error);
    alert('Failed to fetch secret names. Please try again.');
  } finally {
    loading.value = false;
  }
}

const fetchVaultKeys = async () => {
  if (vaultUris.value.length === 0) {
    knownSecretNames.value = {};
    return;
  }
  try {
    const response = await apiFetch('/api/vaults/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(vaultUris.value)
    });
    if (response.ok) {
      const data = await response.json();
      const upperData: Record<string, string[]> = {};
      for (const [uri, names] of Object.entries(data)) {
        upperData[uri] = (names as string[]).map(n => n.toUpperCase());
      }
      knownSecretNames.value = upperData;
    }
  } catch (error) {
    console.error('Failed to fetch keys', error);
  }
}

watch(vaultUris, () => {
  fetchVaultKeys();
}, { deep: true })

const filteredNames = computed(() => {
  const set = new Set<string>();
  Object.values(knownSecretNames.value).flat().forEach(n => set.add(n));
  let names = Array.from(set).sort();

  if (uiSettings.value.nameFilter.trim()) {
    const filters = uiSettings.value.nameFilter.split(',').map(f => f.trim()).filter(f => f);
    names = names.filter(name => {
      for (const f of filters) {
        try {
          if (new RegExp(f, 'i').test(name)) return true;
        } catch {
          if (name.toLowerCase().includes(f.toLowerCase())) return true;
        }
      }
      return false;
    });
  }
  return names;
})

const toggleVisibility = (secretName: string) => {
  if (visibleSecrets.value.has(secretName)) {
    visibleSecrets.value.delete(secretName)
  } else {
    visibleSecrets.value.add(secretName)
  }
}

// Combobox state
const searchQuery = ref('')
const selectedVaultUri = ref('')
const showDropdown = ref(false)
let debounceTimer: ReturnType<typeof setTimeout> | null = null

const fetchProfile = async () => {
  try {
    const response = await apiFetch('/api/profile')
    if (response.ok) {
      profile.value = await response.json()
    }
  } catch (error) {
    console.error('Failed to fetch profile', error)
  }
}

const fetchSubscriptions = async () => {
  try {
    const response = await apiFetch('/api/subscriptions')
    if (response.ok) {
      subscriptions.value = await response.json()
    }
  } catch (error) {
    console.error('Failed to fetch subscriptions', error)
  }
}

const searchVaults = () => {
  if (debounceTimer) clearTimeout(debounceTimer)
  
  const query = searchQuery.value.trim()
  if (query.length < 2) {
    availableVaults.value = []
    showDropdown.value = false
    return
  }

  // Open dropdown immediately while typing
  showDropdown.value = true
  loadingVaults.value = true

  debounceTimer = setTimeout(async () => {
    try {
      let url = `/api/vaults?query=${encodeURIComponent(searchQuery.value)}`
      if (selectedSubscriptionId.value) {
        url += `&subscriptionId=${encodeURIComponent(selectedSubscriptionId.value)}`
      }
      const response = await apiFetch(url)
      if (response.ok) {
        availableVaults.value = await response.json()
      }
    } catch (error) {
      console.error('Failed to fetch available vaults', error)
    } finally {
      loadingVaults.value = false
    }
  }, 350)
}

const unselectedAvailableVaults = computed(() => {
  return availableVaults.value.filter(v => !vaultUris.value.includes(v.uri))
})

const selectVault = (vault: DiscoveredVault) => {
  if (!vaultUris.value.includes(vault.uri)) {
    vaultUris.value.push(vault.uri)
  }
  selectedVaultUri.value = ''
  // Focus remains and dropdown can stay open to select more, or close on blur/esc
}

// Hide dropdown when clicking outside
const hideDropdown = () => {
  setTimeout(() => { showDropdown.value = false }, 200)
}

onMounted(() => {
  fetchProfile()
  fetchSubscriptions()

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      copiedCell.value = null;
    }
  });

  document.addEventListener('focusin', (e) => {
    if (!(e.target as HTMLElement).closest('table')) {
      copiedCell.value = null;
    }
  });
  
  document.addEventListener('click', (e) => {
    if (!(e.target as HTMLElement).closest('td')) {
      copiedCell.value = null;
    }
  });
})



const removeVault = (index: number) => {
  vaultUris.value.splice(index, 1)
}

const forgetAllNames = () => {
  knownSecretNames.value = {};
}

const fetchValuesForVault = async (uri: string) => {
  if (!vaultData.value[uri]) {
    vaultData.value[uri] = {};
  }
  
  // Set status to loading for visible names
  const namesToFetch = filteredNames.value.slice(0, uiSettings.value.resultLimit > 0 ? uiSettings.value.resultLimit : undefined);
  namesToFetch.forEach(name => {
    vaultData.value[uri][name] = { value: null, status: 'Loading' };
  });

  try {
    const response = await apiFetch('/api/vault/values', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        vaultUri: uri,
        secretNames: namesToFetch
      })
    })
    
    if (response.ok) {
      const data = await response.json()
      // Merge with existing
      vaultData.value[uri] = { ...vaultData.value[uri], ...data }
    } else {
      console.error('Failed to fetch values for vault', uri)
    }
  } catch (error) {
    console.error(error)
  }
}

const fetchButtonText = computed(() => {
  if (loading.value) return 'Fetching...';
  const limit = uiSettings.value.resultLimit;
  return limit > 0 ? `Fetch ${limit} Values` : 'Fetch All Values';
});

const fetchButtonTitle = computed(() => {
  const limit = uiSettings.value.resultLimit;
  return limit > 0 
    ? `Fetch the values of the first ${limit} names displayed, as per the limit.` 
    : 'Fetch all values from all names.';
});

const copiedCell = ref<{uri: string, secretName: string} | null>(null);

const handleCopy = async (uri: string, secretName: string, value: string | null | undefined) => {
  if (!value) return;
  internalClipboard.value = value;
  copiedCell.value = { uri, secretName };
  try {
    await navigator.clipboard.writeText(value);
  } catch (e) {
    console.warn('Clipboard write failed, using internal clipboard only');
  }
};

const handlePaste = async (uri: string, secretName: string, currentStatus: SecretValueStatus | undefined) => {
  if (!currentStatus) return;
  let pasteValue = internalClipboard.value;
  try {
    const text = await navigator.clipboard.readText();
    if (text) pasteValue = text;
  } catch (e) {
    // Fallback to internal clipboard
  }

  if (!pasteValue || pasteValue === currentStatus.value) return;

  const originalValue = currentStatus.isStaged 
    ? stagedChanges.value.find(s => s.vaultUri === uri && s.secretName === secretName)?.originalValue || null
    : currentStatus.value;

  const type = (originalValue === null || currentStatus.status === 'Missing' || currentStatus.status === 'Not Retrieved') ? 'CREATE' : 'UPDATE';

  const existingIndex = stagedChanges.value.findIndex(s => s.vaultUri === uri && s.secretName === secretName);
  
  if (pasteValue === originalValue) {
    if (existingIndex >= 0) stagedChanges.value.splice(existingIndex, 1);
    return;
  }

  if (existingIndex >= 0) {
    stagedChanges.value[existingIndex].newValue = pasteValue;
  } else {
    stagedChanges.value.push({ vaultUri: uri, secretName, originalValue, newValue: pasteValue, type });
  }
};

const revertChange = (uri: string, secretName: string) => {
  const index = stagedChanges.value.findIndex(s => s.vaultUri === uri && s.secretName === secretName);
  if (index >= 0) stagedChanges.value.splice(index, 1);
};

const downloadScript = () => {
  if (stagedChanges.value.length === 0) return;

  let script = `# Key Vault Comparer - Apply Staged Changes\n`;
  script += `# This script applies your staged changes with Optimistic Locking verification.\n\n`;

  stagedChanges.value.forEach(change => {
    const vaultName = getVaultName(change.vaultUri);
    script += `# --- Secret: ${change.secretName} in ${vaultName} ---\n`;
    
    if (change.type === 'UPDATE' && change.originalValue) {
      script += `$current = az keyvault secret show --vault-name "${vaultName}" --name "${change.secretName}" --query "value" -o tsv 2>$null\n`;
      script += `if ($current -cne '${change.originalValue.replace(/'/g, "''")}') {\n`;
      script += `    Write-Warning "Optimistic locking failed for ${change.secretName} in ${vaultName}. Current value does not match expected original value. Skipping."\n`;
      script += `} else {\n`;
      script += `    az keyvault secret set --vault-name "${vaultName}" --name "${change.secretName}" --value '${change.newValue.replace(/'/g, "''")}' | Out-Null\n`;
      script += `    Write-Host "Updated ${change.secretName} in ${vaultName} successfully." -ForegroundColor Green\n`;
      script += `}\n`;
    } else if (change.type === 'CREATE') {
      script += `$exists = az keyvault secret show --vault-name "${vaultName}" --name "${change.secretName}" --query "id" -o tsv 2>$null\n`;
      script += `if ($exists) {\n`;
      script += `    Write-Warning "Secret ${change.secretName} already exists in ${vaultName}. Skipping create."\n`;
      script += `} else {\n`;
      script += `    az keyvault secret set --vault-name "${vaultName}" --name "${change.secretName}" --value '${change.newValue.replace(/'/g, "''")}' | Out-Null\n`;
      script += `    Write-Host "Created ${change.secretName} in ${vaultName} successfully." -ForegroundColor Green\n`;
      script += `}\n`;
    }
    script += `\n`;
  });

  const blob = new Blob([script], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'apply_secrets.ps1';
  a.click();
  URL.revokeObjectURL(url);
};

const filteredResults = computed(() => {
  let res = results.value;

  if (uiSettings.value.showStagedOnly) {
    res = res.filter(row => 
      stagedChanges.value.some(s => s.secretName === row.secretName && vaultUris.value.includes(s.vaultUri))
    );
  }

  if (uiSettings.value.statusFilter !== 'Any') {
    res = res.filter(r => r.globalStatus === uiSettings.value.statusFilter)
  }
  
  if (uiSettings.value.securityByRow || uiSettings.value.securityByCol) {
    res = res.filter(row => {
      return Object.entries(row.vaultValues).some(([uri, status]) => {
        const valStr = status.value as string | null;
        if (!valStr || securitySettings.value.ignoreValues.includes(valStr.toLowerCase())) {
          return false;
        }
        
        if (uiSettings.value.securityByRow && rowUsageCount.value.get(row.secretName + valStr)! > 1) {
          return true;
        }
        
        if (uiSettings.value.securityByCol && colUsageCount.value.get(uri + valStr)! > 1) {
          return true;
        }
        
        return false;
      });
    });
  }
  
  return res;
})

const getVaultName = (uri: string) => {
  try {
    return new URL(uri).hostname.split('.')[0]
  } catch {
    return uri
  }
}

const getValueColor = (colorIndex: number | undefined) => {
  switch (colorIndex) {
    case 1: return 'text-emerald-500'
    case 2: return 'text-blue-500'
    case 3: return 'text-amber-500'
    case 4: return 'text-fuchsia-500'
    default: return 'text-slate-500'
  }
}



const getCellClasses = (statusObj: SecretValueStatus | undefined) => {
  if (!statusObj) return '';
  if (statusObj.isStaged) {
    return 'bg-amber-50 border-l-[3px] border-l-amber-400 !border-r !border-r-amber-100 shadow-[inset_0_0_8px_rgba(251,191,36,0.15)]';
  }
  switch (statusObj.status?.toLowerCase()) {
    case 'match': return 'bg-emerald-50/50'
    case 'mismatch': return 'bg-amber-50/50'
    case 'missing': return 'bg-rose-50/50'
    default: return ''
  }
}
</script>

<template>
  <div class="h-screen bg-slate-50 text-slate-900 font-sans flex flex-col">
    <!-- Top App Bar -->
    <header class="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-4 sm:px-6 shrink-0 shadow-sm z-30 relative">
      <div class="flex items-center gap-8">
        <div class="flex items-center gap-2 font-bold text-slate-800 tracking-tight">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
          </svg>
          <span class="hidden sm:inline-block">KV Comparer</span>
        </div>
        
        <nav class="flex items-center gap-1">
          <button 
            @click="currentTab = 'dashboard'"
            class="px-3 py-1.5 text-sm font-semibold rounded-md transition-colors"
            :class="currentTab === 'dashboard' ? 'bg-slate-100 text-blue-600' : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'"
          >
            Dashboard
          </button>
          <button 
            @click="currentTab = 'staged'"
            class="px-3 py-1.5 text-sm font-semibold rounded-md transition-colors"
            :class="currentTab === 'staged' ? 'bg-slate-100 text-blue-600' : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'"
          >
            Staged Changes
          </button>
          <button 
            @click="currentTab = 'logs'"
            class="px-3 py-1.5 text-sm font-semibold rounded-md transition-colors"
            :class="currentTab === 'logs' ? 'bg-slate-100 text-blue-600' : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'"
          >
            Logs
          </button>
        </nav>
      </div>

      <div class="flex items-center gap-3">
        <button 
          @click="showHelpDialog = true" 
          class="p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600 rounded-md transition-colors"
          title="Help & About"
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-3a1 1 0 00-.867.5 1 1 0 11-1.731-1A3 3 0 0113 8a3.001 3.001 0 01-2 2.83V11a1 1 0 11-2 0v-1a1 1 0 011-1 1 1 0 100-2zm0 8a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd" />
          </svg>
        </button>

        <div class="h-5 w-px bg-slate-200 mx-1"></div>

        <div class="flex items-center gap-3" v-if="profile">
          <div class="flex items-center gap-2">
            <span class="text-xs text-slate-500 font-medium uppercase tracking-wider hidden md:block">Sub:</span>
            <select 
              v-model="selectedSubscriptionId"
              class="border-none bg-transparent px-1 py-1 text-sm font-semibold text-slate-800 focus:outline-none focus:ring-0 w-32 sm:w-48 truncate cursor-pointer hover:bg-slate-50 rounded"
            >
              <option value="">All Subscriptions</option>
              <option v-for="sub in subscriptions" :key="sub.id" :value="sub.id">
                {{ sub.name }}
              </option>
            </select>
          </div>
          <div 
            class="h-8 w-8 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold shadow-inner text-sm"
            :title="profile.email"
          >
            {{ profile.initials }}
          </div>
        </div>
      </div>
    </header>

    <!-- Main Content Area -->
    <main class="flex-1 overflow-hidden flex flex-col bg-slate-50 p-4 md:p-6 relative z-10">
      
      <!-- Dashboard Tab -->
      <div v-show="currentTab === 'dashboard'" class="w-full mx-auto space-y-4 flex-1 flex flex-col min-h-0">
      
      <!-- Configuration Panel -->
      <div class="shrink-0 bg-white rounded-xl shadow-sm border border-slate-200 p-6 relative z-20">
        <div class="flex flex-col md:flex-row md:items-center gap-6">
          
          <div class="flex-1 flex gap-3 relative">
            <div class="relative w-full md:w-80">
              <input 
                type="text"
                v-model="searchQuery"
                @input="searchVaults"
                @focus="showDropdown = true"
                @blur="hideDropdown"
                @keydown.esc="showDropdown = false"
                placeholder="Search vaults..."
                class="w-full border border-slate-300 rounded-lg px-4 py-2 pr-10 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <div class="absolute right-3 top-2.5 text-slate-400">
                <svg v-if="loadingVaults" class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <svg v-else xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>

              <!-- Dropdown Menu -->
              <ul 
                v-if="showDropdown && unselectedAvailableVaults.length > 0" 
                class="absolute z-50 w-full mt-1 bg-white border border-slate-200 shadow-lg max-h-60 rounded-md overflow-auto py-1"
              >
                <li 
                  v-for="vault in unselectedAvailableVaults" 
                  :key="vault.uri" 
                  @mousedown.prevent="selectVault(vault)"
                  class="px-4 py-2 hover:bg-blue-50 cursor-pointer text-sm text-slate-700"
                >
                  {{ vault.name }}
                </li>
              </ul>
              <div 
                v-else-if="showDropdown && !loadingVaults && unselectedAvailableVaults.length === 0"
                class="absolute z-50 w-full mt-1 bg-white border border-slate-200 shadow-lg rounded-md p-3 text-sm text-slate-500 text-center"
              >
                No unselected vaults found
              </div>
            </div>

          </div>

          <!-- Active Vaults -->
          <div class="flex-[2] flex flex-wrap items-center gap-2">
            <div 
              v-for="(uri, index) in vaultUris" 
              :key="uri" 
              class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-50 text-blue-700 rounded-full text-sm font-medium border border-blue-200"
            >
              <span>{{ getVaultName(uri) }}</span>
              <button 
                @click="removeVault(index)" 
                class="text-blue-400 hover:text-blue-700 focus:outline-none transition-colors"
                title="Remove"
              >
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
              </button>
            </div>
            
            <button 
              v-if="vaultUris.length > 0"
              @click="refetchNames"
              :disabled="loading"
              class="ml-2 px-3 py-1.5 text-sm font-medium text-slate-600 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 hover:text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-200 transition-colors disabled:opacity-50 flex items-center gap-1.5 shadow-sm"
              title="Refresh secret names without fetching values"
            >
              <svg v-if="loading" class="animate-spin h-3.5 w-3.5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
              <svg v-else xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clip-rule="evenodd" />
              </svg>
              Refetch Names
            </button>
            <button 
              v-if="vaultUris.length > 0"
              @click="forgetAllNames"
              class="ml-2 px-3 py-1.5 text-sm font-medium text-slate-600 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 hover:text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-200 transition-colors flex items-center gap-1.5 shadow-sm"
              title="Forget all discovered secret names"
            >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M3.28 2.22a.75.75 0 00-1.06 1.06l14.5 14.5a.75.75 0 101.06-1.06l-1.745-1.745a10.029 10.029 0 003.3-4.38 1.651 1.651 0 000-1.185A10.004 10.004 0 009.999 3a9.956 9.956 0 00-4.744 1.194L3.28 2.22zM7.752 6.69l1.092 1.092a2.5 2.5 0 013.374 3.373l1.091 1.091a4 4 0 00-5.557-5.557z" clip-rule="evenodd" />
                <path d="M10.748 13.93l2.523 2.523a9.987 9.987 0 01-3.27.547c-4.258 0-7.894-2.66-9.337-6.41a1.651 1.651 0 010-1.186A10.007 10.007 0 012.839 6.02L6.07 9.252a4 4 0 004.678 4.678z" />
              </svg>
              Forget Names
            </button>
          </div>

        </div>

        <div class="mt-6 flex flex-col md:flex-row items-center justify-between gap-4 border-t border-slate-100 pt-6">
          <div class="flex flex-col md:flex-row items-center gap-3 w-full md:w-auto">
            <input 
              type="text"
              v-model="uiSettings.nameFilter"
              placeholder="Regex filter (CSV)..."
              class="w-full md:w-64 border border-slate-300 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              @keyup.enter="fetchComparison"
            />
            
            <div class="flex items-center gap-2">
              <span class="text-sm text-slate-500 font-medium">Limit:</span>
              <select 
                v-model="uiSettings.resultLimit"
                class="border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option :value="10">10</option>
                <option :value="50">50</option>
                <option :value="100">100</option>
                <option :value="0">All</option>
              </select>
            </div>

            <button 
              @click="fetchComparison" 
              :disabled="loading || vaultUris.length === 0"
              class="w-full md:w-auto px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-semibold shadow-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              :title="fetchButtonTitle"
            >
              <svg v-if="loading" class="animate-spin -ml-1 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
              {{ fetchButtonText }}
            </button>
          </div>
          
          <div v-if="results.length > 0" class="flex flex-col sm:flex-row items-center gap-4">
            <div class="flex items-center gap-2">
              <span class="text-sm text-slate-500 font-medium">Status:</span>
              <select 
                v-model="uiSettings.statusFilter" 
                class="border border-slate-300 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="Any">Any</option>
                <option value="Match">Exact Matches</option>
                <option value="Mismatch">Differences</option>
                <option value="Missing">Missing Secrets</option>
              </select>
            </div>
            <div class="flex items-center gap-4 bg-white border border-slate-200 rounded-lg px-3 py-1.5 h-[34px]">
              <span class="text-sm text-slate-500 font-medium mr-1">Reused:</span>
              <label class="flex items-center gap-1.5 text-sm text-slate-600 cursor-pointer hover:text-slate-900 transition-colors">
                <input type="checkbox" v-model="uiSettings.securityByRow" class="rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer" />
                By Row
              </label>
              <div class="w-px h-4 bg-slate-200"></div>
              <label class="flex items-center gap-1.5 text-sm text-slate-600 cursor-pointer hover:text-slate-900 transition-colors">
                <input type="checkbox" v-model="uiSettings.securityByCol" class="rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer" />
                By Col
              </label>
            </div>
            <div class="flex items-center gap-2 bg-amber-50 text-amber-700 border border-amber-200 rounded-lg px-3 py-1.5 h-[34px] ml-auto">
              <label class="flex items-center gap-1.5 text-sm font-medium cursor-pointer hover:text-amber-900 transition-colors">
                <input type="checkbox" v-model="uiSettings.showStagedOnly" class="rounded border-amber-300 text-amber-600 focus:ring-amber-500 cursor-pointer" />
                Show Staged Only
              </label>
            </div>
          </div>
        </div>

        <div v-if="results.length > 0" class="mt-4 border-t border-slate-100 pt-4 flex flex-col sm:flex-row items-center gap-4 bg-slate-50/50 -mx-6 px-6 -mb-6 pb-6 rounded-b-xl">
          <div class="flex flex-wrap items-center gap-4">
            <div class="flex items-center gap-4 bg-white border border-slate-200 rounded-lg px-3 py-1.5 h-[34px]">
              <span class="text-sm text-slate-700 font-medium mr-2">Identicons:</span>
              <label class="flex items-center gap-1.5 text-sm text-slate-600 cursor-pointer hover:text-slate-900 transition-colors">
                <input type="checkbox" v-model="uiSettings.identiconsByRow" class="rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer" />
                By Row
              </label>
              <div class="w-px h-4 bg-slate-200"></div>
              <label class="flex items-center gap-1.5 text-sm text-slate-600 cursor-pointer hover:text-slate-900 transition-colors">
                <input type="checkbox" v-model="uiSettings.identiconsByCol" class="rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer" />
                By Col
              </label>
            </div>
            <select 
              v-model="uiSettings.identicolorMode" 
              class="bg-white border border-slate-200 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-slate-300 text-slate-700"
            >
              <option value="ByRow">Identicolor: By Row (Matches)</option>
              <option value="None">Identicolor: None</option>
            </select>
          </div>
        </div>
      </div>

      <!-- Results Data Grid -->
      <div v-if="results.length > 0" class="bg-white rounded-xl shadow-sm border border-slate-200 flex-1 min-h-0 flex flex-col relative z-10">
        <div class="overflow-auto flex-1">
          <table class="w-full text-left text-sm whitespace-nowrap border-collapse">
            <thead class="bg-slate-50 text-slate-600 sticky top-0 z-20 shadow-[0_1px_0_0_#e2e8f0]">
              <tr>
                <th class="w-12 px-4 py-4 text-center sticky left-0 z-30 bg-slate-50 shadow-[1px_0_0_0_#e2e8f0]"></th>
                <th class="px-6 py-4 font-semibold tracking-wider sticky left-[48px] z-30 bg-slate-50 shadow-[1px_0_0_0_#e2e8f0]">Secret Name</th>
                <th v-for="uri in vaultUris" :key="uri" class="px-6 py-4 font-semibold tracking-wider bg-slate-50">
                  <div class="flex items-center gap-2">
                    <span>{{ getVaultName(uri) }}</span>
                    <button 
                      @click="fetchValuesForVault(uri)" 
                      class="text-slate-400 hover:text-blue-600 transition-colors bg-white rounded-full p-1 shadow-sm border border-slate-200"
                      title="Fetch values for this vault"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                    </button>
                  </div>
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr v-for="row in filteredResults" :key="row.secretName" class="hover:bg-slate-50/50 transition-colors group">
                <td class="px-4 py-4 text-center border-r border-slate-100 sticky left-0 z-10 bg-white group-hover:bg-slate-50/50 shadow-[1px_0_0_0_#f1f5f9]">
                  <button 
                    @click="toggleVisibility(row.secretName)"
                    class="text-slate-400 hover:text-slate-700 focus:outline-none transition-colors"
                    title="Show/hide secret"
                  >
                    <svg v-if="visibleSecrets.has(row.secretName)" xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mx-auto" viewBox="0 0 20 20" fill="currentColor">
                      <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                      <path fill-rule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clip-rule="evenodd" />
                    </svg>
                    <svg v-else xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mx-auto opacity-50" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-1.473-1.473A10.014 10.014 0 0019.542 10C18.268 5.943 14.478 3 10 3a9.958 9.958 0 00-4.512 1.074l-1.78-1.781zm4.261 4.26l1.514 1.515a2.003 2.003 0 012.45 2.45l1.514 1.514a4 4 0 00-5.478-5.478z" clip-rule="evenodd" />
                      <path d="M12.454 16.697L9.75 13.992a4 4 0 01-3.742-3.741L2.335 6.578A9.98 9.98 0 00.458 10c1.274 4.057 5.065 7 9.542 7 .847 0 1.669-.105 2.454-.303z" />
                    </svg>
                  </button>
                </td>
                <td class="px-6 py-4 font-medium text-slate-900 border-r border-slate-100 sticky left-[48px] z-10 bg-white group-hover:bg-slate-50/50 shadow-[1px_0_0_0_#f1f5f9]">
                  {{ row.secretName }}
                </td>
                <td 
                  v-for="uri in vaultUris" 
                  :key="uri"
                  class="px-6 py-4 border-r border-slate-100 last:border-r-0 relative focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-400 group/cell transition-colors cursor-cell"
                  tabindex="0"
                  @keydown.ctrl.c.prevent="handleCopy(uri, row.secretName, row.vaultValues[uri]?.value)"
                  @keydown.meta.c.prevent="handleCopy(uri, row.secretName, row.vaultValues[uri]?.value)"
                  @keydown.ctrl.v.prevent="handlePaste(uri, row.secretName, row.vaultValues[uri])"
                  @keydown.meta.v.prevent="handlePaste(uri, row.secretName, row.vaultValues[uri])"
                  :class="[getCellClasses(row.vaultValues[uri]), copiedCell?.uri === uri && copiedCell?.secretName === row.secretName ? '!outline-dashed !outline-2 !outline-blue-500 !outline-offset-[-2px] z-30' : '']"
                >
                  <button 
                    v-if="row.vaultValues[uri]?.isStaged"
                    @click.stop="revertChange(uri, row.secretName)"
                    class="absolute right-2 top-1/2 -translate-y-1/2 opacity-0 group-hover/cell:opacity-100 bg-white shadow border border-slate-200 rounded p-1.5 text-slate-500 hover:text-amber-600 hover:bg-amber-50 hover:border-amber-300 transition-all z-20"
                    title="Revert Change"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
                    </svg>
                  </button>
                  <div class="flex items-center justify-center gap-4">
                    <span v-if="row.vaultValues[uri]?.status === 'Not Retrieved'" class="text-slate-400 italic text-sm font-medium">
                      ?
                    </span>
                    <span v-else-if="row.vaultValues[uri]?.status === 'Loading'" class="text-blue-500 italic text-sm font-medium flex items-center gap-1">
                      <svg class="animate-spin h-3 w-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    </span>
                    <span v-else-if="row.vaultValues[uri]?.status === 'Missing'" class="text-rose-500 italic text-sm font-medium">
                      Not Found
                    </span>
                    <span v-else-if="row.vaultValues[uri]?.status === 'Error'" class="text-rose-500 italic text-sm font-medium">
                      Error
                    </span>
                    <span v-else class="font-mono tracking-widest font-semibold flex items-center gap-2 px-1.5 py-0.5 rounded transition-all duration-200" :class="[uiSettings.identicolorMode === 'ByRow' ? getValueColor(row.vaultValues[uri]?.colorIndex) : '', {'bg-yellow-100 ring-2 ring-yellow-400 shadow-sm': highlightedValue === row.vaultValues[uri]?.value}]">
                      <template v-if="visibleSecrets.has(row.secretName)">
                        <span class="tracking-normal" :class="{'border-b border-rose-400': row.vaultValues[uri]?.isVulnerable}">{{ row.vaultValues[uri]?.value }}</span>
                        <span 
                          v-if="row.vaultValues[uri]?.identiconEmoji" 
                          class="cursor-pointer hover:scale-125 transition-transform text-lg drop-shadow-sm ml-1"
                          :title="row.vaultValues[uri]?.isVulnerable ? row.vaultValues[uri]?.vulnerableTooltip : 'Value Identicon'"
                          @click.stop="toggleHighlight(row.vaultValues[uri]?.value)"
                        >
                          {{ row.vaultValues[uri]?.identiconEmoji }}
                        </span>
                      </template>
                      <template v-else>
                        <span :class="{'border-b border-rose-400': row.vaultValues[uri]?.isVulnerable}">******</span>
                        <span 
                          v-if="row.vaultValues[uri]?.identiconEmoji" 
                          class="cursor-pointer hover:scale-125 transition-transform text-lg drop-shadow-sm ml-1"
                          :title="row.vaultValues[uri]?.isVulnerable ? row.vaultValues[uri]?.vulnerableTooltip : 'Value Identicon'"
                          @click.stop="toggleHighlight(row.vaultValues[uri]?.value)"
                        >
                          {{ row.vaultValues[uri]?.identiconEmoji }}
                        </span>
                      </template>
                    </span>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Empty State -->
      <div v-else class="bg-white rounded-xl shadow-sm border border-slate-200 border-dashed p-12 flex flex-col items-center justify-center text-center relative z-10">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 text-slate-300 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <h3 class="text-lg font-medium text-slate-900">No comparisons yet</h3>
        <p class="mt-1 text-slate-500">Select multiple Key Vaults from the configuration panel and click Compare to view differences.</p>
      </div>

      <!-- Azure Auth Error Modal -->
      <div v-if="showAuthError" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
        <div class="bg-white rounded-xl shadow-xl w-full max-w-md overflow-hidden transform transition-all">
          <div class="p-6">
            <div class="flex items-center gap-4 mb-4 text-rose-600">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <h3 class="text-xl font-bold text-slate-900">Autenticación Requerida</h3>
            </div>
            <p class="text-slate-600 mb-6">
              Tu sesión de Azure CLI ha expirado o no fue encontrada. Para continuar, abre una terminal en tu computadora y ejecuta:
            </p>
            <div class="bg-slate-100 rounded-lg p-3 flex items-center justify-between mb-6 border border-slate-200">
              <code class="text-slate-800 font-mono text-sm font-semibold">az login</code>
            </div>
            <p class="text-slate-500 text-sm mb-6">
              Una vez que inicies sesión en el navegador que se abrirá, regresa a esta ventana y presiona Reintentar.
            </p>
            <div class="flex justify-end">
              <button 
                @click="retryAuth" 
                class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors shadow-sm"
              >
                Reintentar
              </button>
            </div>
          </div>
        </div>
      </div>

      </div>
      
      <!-- Staged Changes Tab -->
      <div v-if="currentTab === 'staged'" class="w-full mx-auto flex-1 flex flex-col min-h-0">
        <div v-if="stagedChanges.length === 0" class="flex-1 flex flex-col items-center justify-center text-slate-500">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 mb-4 text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
          </svg>
          <h2 class="text-xl font-bold text-slate-700">No Staged Changes</h2>
          <p class="mt-2 text-sm max-w-md text-center">Modifications made in the Dashboard will appear here for review before applying them to Azure Key Vault.</p>
        </div>
        <div v-else class="flex-1 flex flex-col bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <div class="p-6 border-b border-slate-200 flex items-center justify-between bg-slate-50/50 shrink-0">
            <div>
              <h2 class="text-xl font-bold text-slate-900">Review Staged Changes</h2>
              <p class="text-slate-500 text-sm mt-1">You have {{ stagedChanges.length }} pending modification(s).</p>
            </div>
            <div class="flex items-center gap-3">
              <button 
                @click="downloadScript"
                class="px-4 py-2 bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 rounded-lg text-sm font-semibold shadow-sm transition-colors flex items-center gap-2"
                title="Download PowerShell script for all changes"
              >
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Script
              </button>
              <button class="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-semibold shadow-sm transition-colors flex items-center gap-2">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
                Apply Up To 5 Changes at Once
              </button>
            </div>
          </div>
          <div class="flex-1 overflow-auto">
            <table class="w-full text-left border-collapse">
              <thead>
                <tr class="bg-slate-50 border-b border-slate-200 text-slate-500 text-xs uppercase tracking-wider sticky top-0 shadow-sm z-10">
                  <th class="px-6 py-3 font-semibold bg-slate-50">Vault</th>
                  <th class="px-6 py-3 font-semibold bg-slate-50">Secret Name</th>
                  <th class="px-6 py-3 font-semibold bg-slate-50">Action</th>
                  <th class="px-6 py-3 font-semibold bg-slate-50">Original Value</th>
                  <th class="px-6 py-3 font-semibold bg-slate-50">New Value</th>
                  <th class="px-6 py-3 font-semibold bg-slate-50 text-right"></th>
                </tr>
              </thead>
              <tbody class="text-sm divide-y divide-slate-100">
                <tr v-for="(change, idx) in stagedChanges" :key="idx" class="hover:bg-slate-50 transition-colors">
                  <td class="px-6 py-4 font-medium text-slate-700">{{ getVaultName(change.vaultUri) }}</td>
                  <td class="px-6 py-4 font-medium text-slate-900">{{ change.secretName }}</td>
                  <td class="px-6 py-4">
                    <span 
                      class="px-2 py-1 rounded-md text-xs font-bold"
                      :class="change.type === 'CREATE' ? 'bg-emerald-100 text-emerald-700' : 'bg-blue-100 text-blue-700'"
                    >
                      {{ change.type }}
                    </span>
                  </td>
                  <td class="px-6 py-4 text-slate-500 font-mono text-xs max-w-xs truncate" :title="change.originalValue || ''">
                    {{ change.originalValue || '(Missing)' }}
                  </td>
                  <td class="px-6 py-4 font-mono text-xs max-w-xs truncate text-amber-600" :title="change.newValue">
                    {{ change.newValue }}
                  </td>
                  <td class="px-6 py-4 text-right">
                    <button 
                      @click="revertChange(change.vaultUri, change.secretName)"
                      class="text-slate-400 hover:text-rose-600 p-1.5 rounded-lg hover:bg-rose-50 transition-colors"
                      title="Revert"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Logs Tab -->
      <div v-if="currentTab === 'logs'" class="w-full h-full flex flex-col items-center justify-center text-slate-500">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 mb-4 text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <h2 class="text-xl font-bold text-slate-700">Audit Logs</h2>
        <p class="mt-2 text-sm max-w-md text-center">Past synchronization events and errors will be listed here.</p>
      </div>

    </main>

    <!-- Azure Auth Error Modal -->
    <div v-if="showAuthError" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
      <div class="bg-white rounded-xl shadow-xl w-full max-w-md overflow-hidden transform transition-all">
        <div class="p-6">
          <div class="flex items-center gap-4 mb-4 text-rose-600">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <h3 class="text-xl font-bold text-slate-900">Autenticación Requerida</h3>
          </div>
          <p class="text-slate-600 mb-6">
            No tenemos conexión con Azure (Tu sesión ha expirado o no fue encontrada). Para continuar, abre la terminal donde está corriendo el servidor y ejecuta:
          </p>
          <div class="bg-slate-100 rounded-lg p-3 flex items-center justify-between mb-6 border border-slate-200">
            <code class="text-slate-800 font-mono text-sm font-semibold">az login</code>
          </div>
          <p class="text-slate-500 text-sm mb-6">
            Alternativamente, puedes apagar el servidor de backend y frontend, y volver a iniciar todo usando el script <code class="font-mono text-slate-700 bg-slate-100 px-1 rounded">start-all.ps1</code>. Una vez conectado, presiona Reintentar.
          </p>
          <div class="flex justify-end">
            <button 
              @click="retryAuth" 
              class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors shadow-sm"
            >
              Reintentar
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Help Dialog -->
    <div v-if="showHelpDialog" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
      <div class="bg-white rounded-xl shadow-xl max-w-lg w-full overflow-hidden flex flex-col">
        <div class="p-6 border-b border-slate-100 flex items-center justify-between">
          <div>
            <h2 class="text-2xl font-bold text-slate-900">Key Vault Comparer</h2>
            <p class="text-slate-500 text-sm mt-1">Compare and sync secrets across environments.</p>
          </div>
          <button @click="showHelpDialog = false" class="text-slate-400 hover:text-slate-600 hover:bg-slate-100 p-1.5 rounded-lg transition-colors">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
            </svg>
          </button>
        </div>
        <div class="p-6 space-y-4 text-sm text-slate-600">
          <p>This tool allows you to easily compare secret values across multiple Azure Key Vaults side-by-side.</p>
          <ul class="list-disc pl-5 space-y-2">
            <li>Search and select multiple vaults from your Azure Subscriptions.</li>
            <li>Identify missing, mismatched, or identical secret values instantly.</li>
            <li>Analyze value entropy, duplication, and potential vulnerabilities.</li>
            <li>Stage changes and review them before deployment.</li>
          </ul>
        </div>
        <div class="p-4 bg-slate-50 border-t border-slate-100 text-right">
          <button @click="showHelpDialog = false" class="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium text-sm hover:bg-blue-700 transition-colors">Got it</button>
        </div>
      </div>
    </div>

  </div>
</template>
