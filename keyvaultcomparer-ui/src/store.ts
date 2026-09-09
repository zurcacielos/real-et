import { reactive } from 'vue';

const state = reactive({
  recentFilters: JSON.parse(localStorage.getItem('recentFilters') || '[]') as string[],
  nameFilter: ''
});

export const appStore = reactive({
  state,

  // Getters
  get availableRecentFilters() {
    return state.recentFilters.filter(x => x !== state.nameFilter);
  },

  // Actions
  setSecretNameFilter(filterText: string) {
    state.nameFilter = filterText;
  },

  applySecretNameFilter() {
    const f = state.nameFilter.trim();
    if (f) {
      const newHistory = [f, ...state.recentFilters.filter(x => x !== f)].slice(0, 10);
      state.recentFilters = newHistory;
      localStorage.setItem('recentFilters', JSON.stringify(newHistory));
    }
  }
});
