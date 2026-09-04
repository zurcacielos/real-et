<script setup lang="ts">
import { ref, computed } from 'vue'

interface SecretValueStatus {
  value: string | null;
  status: string;
}

interface SecretComparisonRow {
  secretName: string;
  vaultValues: Record<string, SecretValueStatus>;
  globalStatus: string;
}

const vaultUris = ref<string[]>(['https://my-vault-1.vault.azure.net/', 'https://my-vault-2.vault.azure.net/'])
const newVaultUrl = ref('')
const results = ref<SecretComparisonRow[]>([])
const loading = ref(false)
const filter = ref('All')

const addVault = () => {
  if (newVaultUrl.value && !vaultUris.value.includes(newVaultUrl.value)) {
    vaultUris.value.push(newVaultUrl.value)
    newVaultUrl.value = ''
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
      body: JSON.stringify({ vaultUris: vaultUris.value })
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

const getStatusColor = (status: string) => {
  switch (status) {
    case 'Match': return 'var(--status-match)'
    case 'Mismatch': return 'var(--status-mismatch)'
    case 'Missing': return 'var(--status-missing)'
    default: return 'transparent'
  }
}
const getStatusBorder = (status: string) => {
  switch (status) {
    case 'Match': return 'var(--status-match-border)'
    case 'Mismatch': return 'var(--status-mismatch-border)'
    case 'Missing': return 'var(--status-missing-border)'
    default: return 'transparent'
  }
}
</script>

<template>
  <div class="app-layout">
    <aside class="sidebar glass-panel">
      <h2>Vault Config</h2>
      
      <div class="vault-list">
        <div v-for="(uri, index) in vaultUris" :key="uri" class="vault-item">
          <span>{{ new URL(uri).hostname.split('.')[0] }}</span>
          <button @click="removeVault(index)" class="btn-icon">×</button>
        </div>
      </div>
      
      <div class="add-vault">
        <input v-model="newVaultUrl" placeholder="https://..." @keyup.enter="addVault" />
        <button @click="addVault" class="btn btn-secondary">Add</button>
      </div>
      
      <button class="btn btn-primary btn-compare" @click="fetchComparison" :disabled="loading">
        {{ loading ? 'Comparing...' : 'Compare Vaults' }}
      </button>

      <div class="filters" v-if="results.length > 0">
        <h3>Filters</h3>
        <select v-model="filter" class="filter-select">
          <option value="All">Show All</option>
          <option value="Match">Exact Matches</option>
          <option value="Mismatch">Differences</option>
          <option value="Missing">Missing Secrets</option>
        </select>
      </div>
    </aside>

    <main class="main-content">
      <header>
        <h1>Key Vault Comparer</h1>
        <p class="subtitle">Side-by-side secret analysis</p>
      </header>

      <div class="grid-container glass-panel" v-if="results.length > 0">
        <table class="compare-table">
          <thead>
            <tr>
              <th>Secret Name</th>
              <th v-for="uri in vaultUris" :key="uri">{{ new URL(uri).hostname.split('.')[0] }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in filteredResults" :key="row.secretName">
              <td class="secret-name">{{ row.secretName }}</td>
              <td 
                v-for="uri in vaultUris" 
                :key="uri"
                class="value-cell"
                :style="{ 
                  backgroundColor: getStatusColor(row.vaultValues[uri]?.status),
                  borderLeft: `3px solid ${getStatusBorder(row.vaultValues[uri]?.status)}`
                }"
              >
                <div class="value-content">
                  <span v-if="row.vaultValues[uri]?.status === 'Missing'" class="text-muted">Not Found</span>
                  <span v-else class="masked-value">******</span>
                  <span class="status-badge">{{ row.vaultValues[uri]?.status }}</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty-state">
        <p>Add some Key Vault URLs and click Compare.</p>
      </div>
    </main>
  </div>
</template>

<style scoped>
.app-layout {
  display: flex;
  width: 100%;
  gap: 2rem;
  padding: 2rem;
}

.sidebar {
  width: 300px;
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
  height: fit-content;
}

.vault-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem;
  background: rgba(0, 0, 0, 0.2);
  border-radius: 6px;
  margin-bottom: 0.5rem;
  font-size: 0.9rem;
}

.btn-icon {
  background: none;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  font-size: 1.2rem;
}

.btn-icon:hover {
  color: white;
}

.add-vault {
  display: flex;
  gap: 0.5rem;
}

.btn-compare {
  width: 100%;
  padding: 1rem;
  font-size: 1rem;
}

.filter-select {
  width: 100%;
  padding: 0.75rem;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border-color);
  color: white;
  border-radius: 6px;
}

.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

header h1 {
  margin: 0;
  font-size: 2.5rem;
  background: linear-gradient(90deg, #60a5fa, #3b82f6);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.subtitle {
  color: var(--text-muted);
  margin-top: 0.5rem;
}

.grid-container {
  overflow-x: auto;
  padding: 1rem;
}

.compare-table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0 0.5rem;
}

th {
  text-align: left;
  padding: 1rem;
  color: var(--text-muted);
  font-weight: 500;
}

td {
  padding: 1rem;
  background: rgba(255, 255, 255, 0.02);
}

.secret-name {
  font-weight: 500;
  border-top-left-radius: 8px;
  border-bottom-left-radius: 8px;
}

.value-cell {
  position: relative;
}

.value-cell:last-child {
  border-top-right-radius: 8px;
  border-bottom-right-radius: 8px;
}

.value-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.masked-value {
  font-family: monospace;
  letter-spacing: 2px;
}

.status-badge {
  font-size: 0.7rem;
  text-transform: uppercase;
  padding: 0.2rem 0.5rem;
  border-radius: 12px;
  background: rgba(0,0,0,0.2);
}

.empty-state {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 300px;
  color: var(--text-muted);
  font-style: italic;
}
</style>
