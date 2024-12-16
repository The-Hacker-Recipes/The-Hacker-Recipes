import { h, onMounted, nextTick, watch } from 'vue'
import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import Placeholder from './components/Placeholder.vue'
import PageNotFound from "./components/PageNotFound.vue"
import News from './components/News.vue'
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
import AsideSponsorsDemo from './components/AsideSponsorsDemo.vue'
import Donate from './components/Donate.vue'
import FooterLinks from './components/FooterLinks.vue';


const isMobileorTablet = useMediaQuery('(max-width: 1279px)')

export default {
  extends: DefaultTheme,
  
  Layout() {

    const route = useRoute()

    return h(DefaultTheme.Layout, null, {
      'aside-ads-before': () => h('div', {}, [h(Donate),h(AsideSponsorsDemo)]),
      //'aside-ads-before': () => h(AsideSponsors), //Final grid
      'aside-ads-after': () => h(Authors),
      // 'doc-before': () => h(Placeholder),
      // 'doc-footer-before': () => isMobile.value ? h(Authors) : h(Placeholder),
      // 'doc-footer-before': () => isMobile.value ? h(Authors) : h(Placeholder),
      'doc-before': () => h(BannerSponsor),
      'doc-bottom': () => h(FooterLinks),
      //'doc-after': () => isMobileorTablet.value ? h(AsideSponsors, { style: { marginTop: '24px' } }) : null, //Final grid
      'doc-footer-before': () =>isMobileorTablet.value? h('div', {}, [h(Donate), h(Authors)]): null,
      'doc-after': () =>isMobileorTablet.value? h(AsideSponsorsDemo, { style: { marginTop: '24px' } }): null,
      'sidebar-nav-before': () => h(News),
      'not-found': () => h(PageNotFound),
    })
  },

  enhanceApp({ app }) {
    app.component('VPSidebarItem', CustomSidebarItem);
    enhanceAppWithTabs(app);
    app.component('Donaters', Donaters)
    app.component('DonationPricingTable', DonationPricingTable)
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
