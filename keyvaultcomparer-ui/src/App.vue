<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'

interface SecretValueStatus {
  value: string | null;
  status: string;
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

const profile = ref<UserProfile | null>(null)
const vaultUris = ref<string[]>([])
const availableVaults = ref<DiscoveredVault[]>([])
const loadingVaults = ref(false)
const results = ref<SecretComparisonRow[]>([])
const loading = ref(false)
const filter = ref('All')
const visibleSecrets = ref(new Set<string>())
const nameFilter = ref('')
const resultLimit = ref(10)

const subscriptions = ref<Array<{id: string, name: string}>>([])
const selectedSubscriptionId = ref(localStorage.getItem('selectedSub') || '')

watch(selectedSubscriptionId, (newId) => {
  localStorage.setItem('selectedSub', newId)
  availableVaults.value = [] // Clear old vault options since the sub changed
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
    const response = await fetch('/api/profile')
    if (response.ok) {
      profile.value = await response.json()
    }
  } catch (error) {
    console.error('Failed to fetch profile', error)
  }
}

const fetchSubscriptions = async () => {
  try {
    const response = await fetch('/api/subscriptions')
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
      const response = await fetch(url)
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
  searchQuery.value = ''
  showDropdown.value = false
  availableVaults.value = [] // Clear options until they type again
}

// Hide dropdown when clicking outside
const hideDropdown = () => {
  setTimeout(() => { showDropdown.value = false }, 200)
}

onMounted(() => {
  fetchProfile()
  fetchSubscriptions()
})

const addVault = () => {
  if (selectedVaultUri.value && !vaultUris.value.includes(selectedVaultUri.value)) {
    vaultUris.value.push(selectedVaultUri.value)
    selectedVaultUri.value = ''
    searchQuery.value = ''
  }
}

const removeVault = (index: number) => {
  vaultUris.value.splice(index, 1)
}

const fetchComparison = async () => {
  if (vaultUris.value.length === 0) return
  
  loading.value = true
  try {
    const response = await fetch('/api/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        vaultUris: vaultUris.value,
        nameFilter: nameFilter.value,
        limit: resultLimit.value
      })
    })
    
    if (response.ok) {
      results.value = await response.json()
    } else {
      console.error('Failed to fetch comparison')
    }
  } catch (error) {
    console.error(error)
  } finally {
    loading.value = false
  }
}

const filteredResults = computed(() => {
  if (filter.value === 'All') return results.value
  return results.value.filter(r => r.globalStatus === filter.value)
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

const getBadgeClasses = (status: string) => {
  switch (status?.toLowerCase()) {
    case 'match': return 'bg-emerald-100 text-emerald-800 border-emerald-200'
    case 'mismatch': return 'bg-amber-100 text-amber-800 border-amber-200'
    case 'missing': return 'bg-rose-100 text-rose-800 border-rose-200'
    default: return 'bg-slate-100 text-slate-800 border-slate-200'
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
  <div class="min-h-screen bg-slate-50 text-slate-900 font-sans p-6 md:p-8">
    <div class="max-w-7xl mx-auto space-y-6">
      
      <!-- Header -->
      <header class="flex flex-col sm:flex-row items-center justify-between gap-4 border-b border-slate-200 pb-4 mb-8">
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
      <div class="bg-white rounded-xl shadow-sm border border-slate-200 p-6 relative z-20">
        <div class="flex flex-col md:flex-row md:items-center gap-6">
          
          <div class="flex-1 flex gap-3 relative">
            <div class="relative w-full md:w-80">
              <input 
                type="text"
                v-model="searchQuery"
                @input="searchVaults"
                @focus="showDropdown = true"
                @blur="hideDropdown"
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
          <div class="flex-[2] flex flex-wrap gap-2">
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
          </div>

        </div>

        <div class="mt-6 flex flex-col md:flex-row items-center justify-between gap-4 border-t border-slate-100 pt-6">
          <div class="flex flex-col md:flex-row items-center gap-3 w-full md:w-auto">
            <input 
              type="text"
              v-model="nameFilter"
              placeholder="Regex filter (CSV)..."
              class="w-full md:w-64 border border-slate-300 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              @keyup.enter="fetchComparison"
            />
            
            <div class="flex items-center gap-2">
              <span class="text-sm text-slate-500 font-medium">Limit:</span>
              <select 
                v-model="resultLimit"
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
              {{ loading ? 'Comparing...' : 'Compare' }}
            </button>
          </div>
          
          <div v-if="results.length > 0" class="flex items-center gap-2">
            <span class="text-sm text-slate-500 font-medium">Filter:</span>
            <select 
              v-model="filter" 
              class="border border-slate-300 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="All">Show All</option>
              <option value="Match">Exact Matches</option>
              <option value="Mismatch">Differences</option>
              <option value="Missing">Missing Secrets</option>
            </select>
          </div>
        </div>
      </div>

      <!-- Results Data Grid -->
      <div v-if="results.length > 0" class="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden relative z-10">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm whitespace-nowrap">
            <thead class="bg-slate-50 border-b border-slate-200 text-slate-600">
              <tr>
                <th class="w-12 px-4 py-4 text-center"></th>
                <th class="px-6 py-4 font-semibold tracking-wider">Secret Name</th>
                <th v-for="uri in vaultUris" :key="uri" class="px-6 py-4 font-semibold tracking-wider">
                  {{ getVaultName(uri) }}
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr v-for="row in filteredResults" :key="row.secretName" class="hover:bg-slate-50/50 transition-colors">
                <td class="px-4 py-4 text-center border-r border-slate-100">
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
                <td class="px-6 py-4 font-medium text-slate-900 border-r border-slate-100">
                  {{ row.secretName }}
                </td>
                <td 
                  v-for="uri in vaultUris" 
                  :key="uri"
                  class="px-6 py-4 border-r border-slate-100 last:border-r-0"
                  :class="getCellClasses(row.vaultValues[uri]?.status)"
                >
                  <div class="flex items-center justify-center gap-4">
                    <span v-if="row.vaultValues[uri]?.status === 'Missing'" class="text-slate-500 italic text-sm font-medium">
                      Not Found
                    </span>
                    <span v-else class="font-mono tracking-widest font-semibold" :class="getValueColor(row.vaultValues[uri]?.colorIndex)">
                      <template v-if="visibleSecrets.has(row.secretName)">
                        <span class="tracking-normal">{{ row.vaultValues[uri]?.value }}</span>
                      </template>
                      <template v-else>
                        ******
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

    </div>
  </div>
</template>
