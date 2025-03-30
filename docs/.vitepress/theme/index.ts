import { h, onMounted, nextTick, watch } from 'vue'
import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import Placeholder from './components/Placeholder.vue'
import PageNotFound from "./components/PageNotFound.vue"
import Authors from './components/Authors.vue'
import CustomSidebarItem from './components/CustomSidebarItem.vue'
import './custom.css'
import mediumZoom from 'medium-zoom'
import { useMediaQuery } from '@vueuse/core'
import { useRoute } from 'vitepress'
import { enhanceAppWithTabs } from 'vitepress-plugin-tabs/client'
import Donaters from './components/Donaters.vue'
import DonationPricingTable from './components/DonationPricingTable.vue'
import BannerSponsor from './components/BannerSponsor.vue'
import AsideSponsors from './components/AsideSponsors.vue'
import Donate from './components/Donate.vue'
import FooterLinks from './components/FooterLinks.vue';
import variableCommands from "vitepress-md-var";
import ExegolHistoryImport from './components/ExegolHistoryImport.vue'
const isMobileorTablet = useMediaQuery('(max-width: 1279px)')


// Storage key for persisting variables
const STORAGE_KEY = 'thr_commands_variables';
// 24 hours in milliseconds
const EXPIRY_TIME = 24 * 60 * 60 * 1000;

/**
 * Stores variable value to localStorage with expiration
 * @param varName - name of variable to store
 * @param varValue - value of variable to store
 */
function storeVar(varName, varValue) {
  const values = loadVarValues();
  try {
    values.set(varName, varValue);
    const dataToStore = {
      timestamp: Date.now(),
      values: Object.fromEntries(values)
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(dataToStore));
  } catch (e) {
    console.error('Failed to save variable values:', e);
  }
}

/**
 * Loads variable values from localStorage if not expired
 * @returns Map of variable names and their saved values
 */
function loadVarValues() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (!saved) return new Map();
    
    const data = JSON.parse(saved);
    const now = Date.now();
    
    // Check if data has expired (24 hours)
    if (data.timestamp && now - data.timestamp > EXPIRY_TIME) {
      // Data expired, remove it and return empty map
      localStorage.removeItem(STORAGE_KEY);
      return new Map();
    }
    
    // Data still valid
    return new Map(Object.entries(data.values || {}));
  } catch (e) {
    console.error('Failed to load variable values:', e);
    return new Map();
  }
}

export default {
  extends: DefaultTheme,
  
  Layout() {

    const route = useRoute()

    return h(DefaultTheme.Layout, null, {
      'aside-ads-before': () =>  h('div', {}, [h(Donate),h(AsideSponsors)]), 
      'aside-ads-after': () => h(Authors),
      'doc-before': () => h(BannerSponsor),
      'doc-bottom': () => h(FooterLinks),
      'doc-footer-before': () =>isMobileorTablet.value? h('div', {}, [h(Donate), h(Authors)]): null,
      'doc-after': () =>isMobileorTablet.value? h(AsideSponsors, { style: { marginTop: '24px' } }): null,
      'not-found': () => h(PageNotFound),
    })
  },

  enhanceApp({ app }) {
    app.component('VPSidebarItem', CustomSidebarItem);
    enhanceAppWithTabs(app);
    app.component('Donaters', Donaters)
    app.component('DonationPricingTable', DonationPricingTable)
    app.component('ExegolHistoryImport', ExegolHistoryImport)
  },

  // IMG ZOOM SETUP
  setup() {
    const route = useRoute()

    const initZoom = () => {
      const margin = isMobileorTablet.value ? 0 : 150
      mediumZoom('.main img', { background: 'var(--vp-c-bg)', margin })
    }

    onMounted(() => {
      initZoom()
    })

    watch(
      () => route.path,
      () => nextTick(() => initZoom())
    )

    variableCommands(route, {
      loadVar: varName => loadVarValues().get(varName),
      storeVar: (varName, varValue) => storeVar(varName, varValue),
      styling: "thr",
    })
  },
} satisfies Theme
