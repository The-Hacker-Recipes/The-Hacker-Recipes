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


const ALL_CATEGORIES = ['intro', 'ad', 'web', 'infra', 'evasion', 'physical', 'intelligence-gathering', 'radio', 'mobile-apps', 'contribute', 'policies']

const ALL_COUNTRIES = [
  "AF", "AX", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW", "AU", "AT", "AZ", "BS", "BH", "BD", "BB", "BY", "BE",
  "BZ", "BJ", "BM", "BT", "BO", "BQ", "BA", "BW", "BV", "BR", "IO", "BN", "BG", "BF", "BI", "CV", "KH", "CM", "CA", "KY", "CF", "TD",
  "CL", "CN", "CX", "CC", "CO", "KM", "CG", "CD", "CK", "CR", "CI", "HR", "CU", "CW", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC", "EG",
  "SV", "GQ", "ER", "EE", "ET", "FK", "FO", "FJ", "FI", "FR", "GF", "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", "GR", "GL", "GD",
  "GP", "GU", "GT", "GG", "GN", "GW", "GY", "HT", "HM", "VA", "HN", "HK", "HU", "IS", "IN", "ID", "IR", "IQ", "IE", "IM", "IL", "IT",
  "JM", "JP", "JE", "JO", "KZ", "KE", "KI", "KP", "KR", "KW", "KG", "LA", "LV", "LB", "LS", "LR", "LY", "LI", "LT", "LU", "MO", "MK",
  "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT", "MX", "FM", "MD", "MC", "MN", "ME", "MS", "MA", "MZ", "MM", "NA",
  "NR", "NP", "NL", "NC", "NZ", "NI", "NE", "NG", "NU", "NF", "MP", "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", "PH", "PN",
  "PL", "PT", "PR", "QA", "RE", "RO", "RU", "RW", "BL", "SH", "KN", "LC", "MF", "PM", "VC", "WS", "SM", "ST", "SA", "SN", "RS", "SC",
  "SL", "SG", "SX", "SK", "SI", "SB", "SO", "ZA", "GS", "SS", "ES", "LK", "SD", "SR", "SJ", "SZ", "SE", "CH", "SY", "TW", "TJ", "TZ",
  "TH", "TL", "TG", "TK", "TO", "TT", "TN", "TR", "TM", "TC", "TV", "UG", "UA", "AE", "GB", "US", "UM", "UY", "UZ", "VU", "VE", "VN",
  "VG", "VI", "WF", "EH", "YE", "ZM", "ZW"
];

// shared data across instances so we load only once.
const data = ref()

// Set dataHost to an empty string since images are local
const dataHost = ''

const viteSponsors: Pick<Sponsors, 'special' | 'gold' | 'banner'> = {
  special: [
    {
      name: 'Demo1',
      categories: ['demo'],
      country: 'all',
      url: 'https://www.example.com',
      img: '/images/sponsors/Logo_demo1.svg',
    },
    {
      name: 'Advertise',
      categories: ['all'],
      country: 'all',
      url: '/contributing/ads',
      img: '/images/sponsors/advertise.svg',
    }
  ],
  gold: [
    {
      name: 'Demo2',
      categories: ['demo'],
      country: 'all',
      url: 'https://www.example.com',
      img: '/images/sponsors/Logo_demo2.svg',
    },
    {
      name: 'Demo3',
      categories: ['demo'],
      country: 'all',
      url: 'https://www.example.com',
      img: '/images/sponsors/Logo_demo3.svg',
    },
    {
      name: 'Algosecure',
      categories: ['all'],
      country: 'FR',
      url: 'https://www.algosecure.fr/',
      img: '/images/sponsors/algosecure.svg',
    },
    {
      name: 'EPIEOS',
      categories: ['all'],
      country: 'all',
      url: 'https://epieos.com/',
      img: '/images/sponsors/epieos.svg',
    }
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

    const mappedSponsors = mapSponsors(viteSponsors).map(sponsorGroup => ({
      ...sponsorGroup,
      items: sponsorGroup.items.map(sponsor => ({
        ...sponsor,
        categories: sponsor.categories.includes('all') ? [...ALL_CATEGORIES] : sponsor.categories,
        country: sponsor.country.includes('all') ? [...ALL_COUNTRIES] : sponsor.country
      }))
    }))

    data.value = mappedSponsors
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
