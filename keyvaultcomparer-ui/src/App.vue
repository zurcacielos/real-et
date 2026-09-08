<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'

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

interface UiSettings {
  identiconsByRow: boolean;
  identiconsByCol: boolean;
  identicolorMode: 'ByRow' | 'None';
  statusFilter: string;
  securityByRow: boolean;
  securityByCol: boolean;
  nameFilter: string;
  resultLimit: number;
}

const defaultUiSettings: UiSettings = {
  identiconsByRow: true,
  identiconsByCol: true,
  identicolorMode: 'ByRow',
  statusFilter: 'Any',
  securityByRow: false,
  securityByCol: false,
  nameFilter: '',
  resultLimit: 50
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
      if (!knownNamesForVault.includes(name)) {
        row.vaultValues[uri] = { status: 'Missing', value: null, colorIndex: 0, isVulnerable: false };
      } else {
        const d = vaultData.value[uri]?.[name];
        row.vaultValues[uri] = d ? { ...d, colorIndex: 0, isVulnerable: false } : { status: 'Not Retrieved', value: null, colorIndex: 0, isVulnerable: false };
      }
      
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


const filteredResults = computed(() => {
  let res = results.value;
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



const getCellClasses = (status: string) => {
  switch (status?.toLowerCase()) {
    case 'match': return 'bg-emerald-50/50'
    case 'mismatch': return 'bg-amber-50/50'
    case 'missing': return 'bg-rose-50/50'
    default: return ''
  }
}
</script>

<template>
  <div class="h-screen bg-slate-50 text-slate-900 font-sans p-4 md:p-6 flex flex-col">
    <div class="w-full mx-auto space-y-4 flex-1 flex flex-col min-h-0">
      
      <!-- Header -->
      <header class="shrink-0 flex flex-col sm:flex-row items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <h1 class="text-3xl font-bold tracking-tight text-slate-900">Key Vault Comparer</h1>
          <p class="text-slate-500 text-sm mt-1">Compare secrets across multiple Azure Key Vaults</p>
        </div>

        <div class="flex items-center gap-4 bg-white px-4 py-2 rounded-full shadow-sm border border-slate-200" v-if="profile">
          <div class="flex items-center gap-2">
            <span class="text-xs text-slate-500 font-medium uppercase tracking-wider hidden sm:block">Subscription:</span>
            <select 
              v-model="selectedSubscriptionId"
              class="border border-slate-300 rounded-md px-2 py-1 text-sm font-semibold text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 w-48 sm:w-64 truncate bg-slate-50"
            >
              <option value="">All Subscriptions</option>
              <option v-for="sub in subscriptions" :key="sub.id" :value="sub.id">
                {{ sub.name }}
              </option>
            </select>
          </div>
          <div class="h-8 w-px bg-slate-200"></div>
          <div 
            class="h-10 w-10 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold shadow-inner"
            :title="profile.email"
          >
            {{ profile.initials }}
          </div>
        </div>
      </header>

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
                <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
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
            >
              <svg v-if="loading" class="animate-spin -ml-1 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
              {{ loading ? 'Fetching...' : 'Fetch All Values' }}
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
                  class="px-6 py-4 border-r border-slate-100 last:border-r-0"
                  :class="getCellClasses(row.vaultValues[uri]?.status)"
                >
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
  </div>
</template>
