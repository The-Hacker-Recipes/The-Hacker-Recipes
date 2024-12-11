<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { createClient } from '@supabase/supabase-js'

// Define types for our data
interface Supporter {
  name_or_link: string
  amount: number      // Now a float column
  currency: string    // New separate column
  created_at: string
  _colorPosition?: number
}

interface ProcessedSupporter {
  displayName: string
  avatar_url?: string
  link?: string
  platform?: 'github' | 'x' | 'linkedin'
  username?: string
  amount: number
  colorStyle: { backgroundColor: string; color: string }
  formattedAmount: string
  wasConverted: boolean
}

const supporters = ref<ProcessedSupporter[]>([])
const error = ref<string | null>(null)
const loading = ref(true)

const supabase = createClient(
  'https://fvenaxmvigueigzjfkls.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZ2ZW5heG12aWd1ZWlnempma2xzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzE1MjgzNjcsImV4cCI6MjA0NzEwNDM2N30.rBWw75mH4NWNMM5ri-qNrCWSr3S_RHHnXoIxHbrRZ2c'
)

// Update the conversion rates with more currencies
const CONVERSION_RATES = {
  USD: 1,
  EUR: 1.08,    // 1 EUR = 1.08 USD
  GBP: 1.26,    // 1 GBP = 1.26 USD
  CAD: 0.74,    // 1 CAD = 0.74 USD
  INR: 0.012,   // 1 INR = 0.012 USD
  AUD: 0.66,    // 1 AUD = 0.66 USD
  NZD: 0.61,    // 1 NZD = 0.61 USD
  SGD: 0.75,    // 1 SGD = 0.75 USD
  CHF: 1.12,    // 1 CHF = 1.12 USD
  JPY: 0.0067   // 1 JPY = 0.0067 USD
}

// Update normalizeAmount function to work with separate amount and currency
function normalizeAmount(amount: number, currency: string): { amount: number; wasConverted: boolean } {
  try {
    if (currency === 'USD') {
      return { amount: amount, wasConverted: false }
    }
    
    const rate = CONVERSION_RATES[currency as keyof typeof CONVERSION_RATES]
    if (!rate) {
      console.warn(`Unknown currency: ${currency}, falling back to USD`)
      return { amount: amount, wasConverted: false }
    }
    
    return { amount: amount * rate, wasConverted: true }
  } catch (e) {
    console.error('Error processing amount:', amount, currency)
    return { amount: 0, wasConverted: false }
  }
}

// Update the getColorStyle function
function getColorStyle(amount: number, maxAmount: number): { backgroundColor: string; color: string } {
  const normalizedValue = amount / maxAmount
  
  const red = Math.round(161 + (255 - 161) * normalizedValue)
  const green = Math.round(98 + (126 - 98) * normalizedValue)
  const blue = Math.round(247 * (1 - normalizedValue))
  
  return {
    backgroundColor: `rgba(${red}, ${green}, ${blue}, 0.1)`,
    color: `rgb(${red}, ${green}, ${blue})`
  }
}

// Update formatAmount to include tilde for converted amounts
function formatAmount(amount: number, wasConverted: boolean): string {
  return `(${wasConverted ? '~' : ''}$${Math.round(amount)})`
}

function processSupporter(supporter: Supporter, maxAmount: number): ProcessedSupporter {
  const { amount, wasConverted } = normalizeAmount(supporter.amount, supporter.currency)
  const processed: ProcessedSupporter = {
    displayName: supporter.name_or_link,
    amount: amount,
    colorStyle: getColorStyle(supporter._colorPosition || 0, 1),
    formattedAmount: formatAmount(amount, wasConverted),
    wasConverted
  }

  if (supporter.name_or_link.includes('github.com')) {
    const username = supporter.name_or_link.replace(/\/$/, '').split('/').pop() || ''
    processed.displayName = username
    processed.link = supporter.name_or_link
    processed.platform = 'github'
    processed.username = username
    processed.avatar_url = `https://github.com/${username}.png`
  } else if (supporter.name_or_link.includes('twitter.com') || 
             supporter.name_or_link.includes('x.com')) {
    const username = supporter.name_or_link.replace(/\/$/, '').split('/').pop() || ''
    processed.displayName = `@${username}`
    processed.link = supporter.name_or_link
    processed.platform = 'x'
    processed.username = username
    processed.avatar_url = `https://unavatar.io/twitter/${username}`
  } else if (supporter.name_or_link.includes('linkedin.com')) {
    const urlParts = supporter.name_or_link.split('linkedin.com/');
    const path = urlParts[1] || '';
    const username = path.replace(/\/$/, '').split('/').filter(Boolean)[1] || '';
    
    processed.displayName = username
    processed.link = supporter.name_or_link
    processed.platform = 'linkedin'
    processed.username = username
  }

  return processed
}

function isWithinLast12Months(dateStr: string): boolean {
  const date = new Date(dateStr)
  const twelveMonthsAgo = new Date()
  twelveMonthsAgo.setMonth(twelveMonthsAgo.getMonth() - 12)
  return date >= twelveMonthsAgo
}

async function getDonaters() {
  try {
    loading.value = true
    error.value = null

    const { data, error: supabaseError } = await supabase
      .from('supporters')
      .select('name_or_link, amount, currency, created_at')

    if (supabaseError) throw supabaseError
    if (!data) throw new Error('No data received from Supabase')

    // Filter out ANON_DONATION entries and those older than 12 months
    const filteredData = data
      .filter(supporter => 
        supporter.name_or_link !== 'ANON_DONATION' && 
        isWithinLast12Months(supporter.created_at)
      )
    
    // Get unique amounts and find the maximum
    const amounts = [...new Set(filteredData.map(s => 
      normalizeAmount(s.amount, s.currency).amount
    ))]
    const maxAmount = Math.max(...amounts)
    
    // Sort amounts in descending order to ensure consistent color assignment
    amounts.sort((a, b) => b - a)
    
    // Create a mapping of amount to its position in the sorted unique amounts
    const amountPositions = new Map(amounts.map((amount, index) => [amount, index / (amounts.length - 1)]))

    supporters.value = filteredData
      .map(supporter => {
        const { amount } = normalizeAmount(supporter.amount, supporter.currency)
        return processSupporter({
          ...supporter,
          _colorPosition: amountPositions.get(amount) || 0
        }, maxAmount)
      })
      .sort((a, b) => b.amount - a.amount)

  } catch (e) {
    console.error('Error fetching supporters:', e)
    error.value = e instanceof Error ? e.message : 'An unknown error occurred'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  getDonaters()
})
</script>

<template>
  <p v-if="error" class="error">{{ error }}</p>
  <p v-else-if="loading" class="loading">Loading supporters...</p>
  <p v-else-if="supporters.length === 0" class="empty">
    No active supporters in the last 12 months.
  </p>
  <div v-else class="supporters">
    <div class="all-supporters">
      <div v-for="supporter in supporters" 
           :key="supporter.username" 
           class="supporter-wrapper">
        <img v-if="supporter.avatar_url" 
             :src="supporter.avatar_url" 
             :alt="supporter.username" 
             class="avatar" />
        <div class="pill" 
             :style="supporter.colorStyle"
             :class="{ 'linked': supporter.link }">
          <a v-if="supporter.link" 
             :href="supporter.link" 
             target="_blank" 
             rel="noopener" 
             class="supporter-content">
            <span>{{ supporter.displayName }}</span>
            <svg v-if="supporter.platform === 'github'" class="icon github-icon" viewBox="0 0 24 24" width="18" height="18">
              <path fill="currentColor" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.462-1.11-1.462-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z"/>
            </svg>
            <svg v-if="supporter.platform === 'x'" class="icon x-icon" viewBox="0 0 24 24" width="16" height="16">
              <path fill="currentColor" d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
            </svg>
            <svg v-if="supporter.platform === 'linkedin'" class="icon linkedin-icon" viewBox="0 0 24 24" width="18" height="18">
              <path fill="currentColor" d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.32 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.79M6.88 8.56a1.68 1.68 0 0 0 1.68-1.68c0-.93-.75-1.69-1.68-1.69a1.69 1.69 0 0 0-1.69 1.69c0 .93.76 1.68 1.69 1.68m1.39 9.94v-8.37H5.5v8.37h2.77z"/>
            </svg>
            <span class="amount">{{ supporter.formattedAmount }}</span>
          </a>
          <span v-else>
            {{ supporter.displayName }}
            <span class="amount">{{ supporter.formattedAmount }}</span>
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.supporters {
  width: 100%;
  margin-top: 24px;
}

.all-supporters {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 12px;
  justify-content: flex-start;
  padding: 4px 0;
}

.supporter-wrapper {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 0;
}

.avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  object-fit: cover;
}

.pill {
  height: 32px;
  padding: 0 12px;
  border-radius: 16px;
  display: inline-flex;
  align-items: center;
  transition: all 0.2s ease;
  border: 1px solid transparent;
}

.pill.linked {
  border: 2px dashed currentColor;
  border-color: color-mix(in srgb, currentColor 30%, transparent);
}

.pill.linked:hover {
  filter: brightness(1.1);
  transform: translateY(-1px);
  cursor: pointer;
  border-color: color-mix(in srgb, currentColor 50%, transparent);
}

.supporter-content {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  text-decoration: none;
  color: inherit !important;
}

.error {
  color: var(--vp-c-danger);
}

.loading, .empty {
  color: var(--vp-c-text-2);
}

/* Add styles for the amount */
.amount {
  font-weight: 400;
  opacity: 0.7;
  margin-left: 4px;
  font-size: 0.9em;
}

/* Override any default link hover behavior */
.supporter-content:hover {
  color: inherit !important;
  opacity: 1;
}

.pill:hover .supporter-content {
  color: inherit !important;
}

.icon {
  display: inline-flex;
  align-items: center;
  margin-left: 6px;
  margin-right: 0;
  opacity: 0.8;
  transform: scale(1.1);
}

.github-icon {
  margin-top: 0px;
}

.x-icon {
  margin-top: 1px;
}

.linkedin-icon {
  margin-top: 0px;
}

.pill:hover .icon {
  opacity: 1;
}
</style> 