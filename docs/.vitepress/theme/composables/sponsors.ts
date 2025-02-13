import { onMounted, onUnmounted, ref } from 'vue'

interface Sponsors {
  special: Sponsor[]
  platinum: Sponsor[]
  platinum_china: Sponsor[]
  gold: Sponsor[]
  silver: Sponsor[]
  bronze: Sponsor[]
  banner: BannerSponsor[] 
}

interface Sponsor {
  name: string
  categories: string[]
  country: string
  img: string
  url: string
  hasDark?: true
}

interface BannerSponsor {
  name: string
  url: string
  tagline: string
  description: string
  categories: string[]
  country: string
  lightTheme: {
    primaryColor: string
    secondaryColor: string
    logo: string
  }
  darkTheme: {
    primaryColor: string
    secondaryColor: string
    logo: string
  }
}

// shared data across instances so we load only once.
const data = ref()

// Set dataHost to an empty string since images are local
const dataHost = ''

const viteSponsors: Pick<Sponsors, 'special' | 'gold' | 'banner'> = {
  special: [
    {
      name: 'Demo1',
      categories: ['demo'],
      country: 'FR',
      url: 'https://www.example.com',
      img: '/images/sponsors/Logo_demo1.svg',
    }
  ],
  gold: [
    {
      name: 'Demo2',
      categories: ['demo'],
      country: 'FR',
      url: 'https://www.example.com',
      img: '/images/sponsors/Logo_demo2.svg',
    },
    {
      name: 'Demo3',
      categories: ['demo'],
      country: 'FR',
      url: 'https://www.example.com',
      img: '/images/sponsors/Logo_demo3.svg',
    },
  ],
  banner: [
    {
      name: 'Fictional Company',
      url: 'https://www.example.com',
      tagline: 'Your trusted partner in innovation.',
      description: "This is a placeholder for impactful text designed to attract and engage users. Showcase your vision, values, and why people should trust and choose your services.",
      categories: ['demo'],
      country: 'FR',
      lightTheme: {
        primaryColor: '#e141d999',
        secondaryColor: '#8071f199',
        logo: '/images/sponsors/logo_light.png'
      },
      darkTheme: {
        primaryColor: '#ba66ff99',
        secondaryColor: '#ff6ee799',
        logo: '/images/sponsors/logo_dark.png'
      }
    }
  ]
}

function toggleDarkLogos() {
  if (data.value) {
    const isDark = document.documentElement.classList.contains('dark')
    data.value.forEach(({ items }) => {
      items.forEach((s: Sponsor) => {
        if (s.hasDark) {
          s.img = isDark
            ? s.img.replace(/(\.\w+)$/, '-dark$1')
            : s.img.replace(/-dark(\.\w+)$/, '$1')
        }
      })
    })
  }
}

export function useSponsor() {
  onMounted(() => {
    const ob = new MutationObserver((list) => {
      for (const m of list) {
        if (m.attributeName === 'class') {
          toggleDarkLogos()
        }
      }
    })
    ob.observe(document.documentElement, { attributes: true })
    onUnmounted(() => {
      ob.disconnect()
    })

    if (data.value) {
      return
    }

    // Use local static data
    data.value = mapSponsors(viteSponsors)
    toggleDarkLogos()
  })

  return {
    data,
  }
}

function mapSponsors(sponsors: Pick<Sponsors, 'special' | 'gold' | 'banner'>) {
  return [
    {
      tier: 'Special Sponsors',
      size: 'big',
      items: sponsors['special'],
    },
    {
      tier: 'Gold Sponsors',
      size: 'small',
      items: sponsors['gold'],
    },
    {
      tier: 'Banner Sponsors',
      size: 'medium',
      items: sponsors['banner'],
    },
  ]
}

const viteSponsorNames = new Set(
  Object.values(viteSponsors).flatMap((sponsors) =>
    sponsors.map((s) => s.name),
  ),
)

/**
 * Map Vue/Vite sponsors data to objects and filter out Vite-specific sponsors
 */
function mapImgPath(sponsors: Sponsor[]) {
  return sponsors
    .filter((sponsor) => !viteSponsorNames.has(sponsor.name))
    .map((sponsor) => ({
      ...sponsor,
      img: `${dataHost}${sponsor.img}`, // Use local path
    }))
}
