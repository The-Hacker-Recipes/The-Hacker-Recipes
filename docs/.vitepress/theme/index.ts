import { h, onMounted, nextTick, watch } from 'vue'
import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import Placeholder from './components/Placeholder.vue'
import PageNotFound from "./components/PageNotFound.vue"
import News from './components/News.vue'
import Authors from './components/Authors.vue'
import CustomSidebarItem from './components/CustomSidebarItem.vue';
import './custom.css'
import mediumZoom from 'medium-zoom'
import { useMediaQuery } from '@vueuse/core'
import { useRoute } from 'vitepress'
import { enhanceAppWithTabs } from 'vitepress-plugin-tabs/client'

const isMobileorTablet = useMediaQuery('(max-width: 1279px)')

export default {
  extends: DefaultTheme,
  
  Layout() {

    return h(DefaultTheme.Layout, null, {
      // 'aside-ads-before': () => h(Placeholder),
      'aside-ads-before': () => h(Authors),
      // 'doc-before': () => h(Placeholder),
      // 'doc-footer-before': () => isMobile.value ? h(Authors) : h(Placeholder),
      // 'doc-footer-before': () => isMobile.value ? h(Authors) : h(Placeholder),
      'doc-footer-before': () => isMobileorTablet.value ? h(Authors) : null,
      // 'aside-outline-after': () => isMobile.value ? null : h(Authors),
      // 'nav-screen-content-after': () => h(Placeholder),
      'sidebar-nav-before': () => h(News),
      'not-found': () => h(PageNotFound),
    })
  },

  enhanceApp({ app }) {
    app.component('VPSidebarItem', CustomSidebarItem);
    enhanceAppWithTabs(app);
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
  },
} satisfies Theme
