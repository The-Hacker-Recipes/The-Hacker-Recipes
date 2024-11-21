<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { createClient } from '@supabase/supabase-js'

// Define types for our data
interface Supporter {
  name_or_link: string
  product: string
  created_at: string
}

interface GroupedSupporters {
  'Golden Chef': ProcessedSupporter[]
  'Breakfast Club': ProcessedSupporter[]
  'Cereal Bowl': ProcessedSupporter[]
  'Choco Chip': ProcessedSupporter[]
}

const supporterGroups = ref<GroupedSupporters>({
  'Golden Chef': [],
  'Breakfast Club': [],
  'Cereal Bowl': [],
  'Choco Chip': []
})
const error = ref<string | null>(null)
const loading = ref(true)

const supabase = createClient(
  'https://fvenaxmvigueigzjfkls.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZ2ZW5heG12aWd1ZWlnempma2xzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzE1MjgzNjcsImV4cCI6MjA0NzEwNDM2N30.rBWw75mH4NWNMM5ri-qNrCWSr3S_RHHnXoIxHbrRZ2c'
)

interface ProcessedSupporter {
  displayName: string
  avatar_url?: string
  link?: string
  platform?: 'github' | 'x'
  username?: string
}

function processSupporter(supporter: Supporter): ProcessedSupporter {
  const processed: ProcessedSupporter = {
    displayName: supporter.name_or_link
  }

  if (supporter.name_or_link.includes('github.com')) {
    const username = supporter.name_or_link.split('/').pop() || ''
    processed.displayName = username
    processed.link = supporter.name_or_link
    processed.platform = 'github'
    processed.username = username
    processed.avatar_url = `https://github.com/${username}.png`
  } else if (supporter.name_or_link.includes('twitter.com') || supporter.name_or_link.includes('x.com')) {
    const username = supporter.name_or_link.split('/').pop() || ''
    processed.displayName = `@${username}`
    processed.link = supporter.name_or_link
    processed.platform = 'x'
    processed.username = username
    processed.avatar_url = `https://unavatar.io/twitter/${username}`
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
      .select('name_or_link, product, created_at')

    if (supabaseError) throw supabaseError
    if (!data) throw new Error('No data received from Supabase')

    Object.keys(supporterGroups.value).forEach(key => {
      supporterGroups.value[key as keyof GroupedSupporters] = []
    })

    for (const supporter of data) {
      if (isWithinLast12Months(supporter.created_at)) {
        const processed = processSupporter(supporter)
        if (supporter.product in supporterGroups.value) {
          supporterGroups.value[supporter.product as keyof GroupedSupporters].push(processed)
        }
      }
    }
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
  <p v-else-if="Object.values(supporterGroups).every(group => group.length === 0)" class="empty">
    No active supporters in the last 12 months.
  </p>
  <div v-else class="supporters">
    <div class="all-supporters">
      <div v-for="(group, key) in supporterGroups" :key="key" class="supporter-group">
        <div v-for="(supporter, index) in group" 
             :key="index" 
             class="supporter-wrapper">
          <img v-if="supporter.avatar_url" 
               :src="supporter.avatar_url" 
               :alt="supporter.username" 
               class="avatar" />
          <div :class="['pill', key.toLowerCase().replace(' ', '-'), { 'linked': supporter.link }]">
            <a v-if="supporter.link" 
               :href="supporter.link" 
               target="_blank" 
               rel="noopener" 
               class="supporter-content">
              <span>{{ supporter.displayName }}</span>
              <svg v-if="supporter.platform === 'github'" class="icon github-icon" viewBox="0 0 24 24" width="16" height="16">
                <path fill="currentColor" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.462-1.11-1.462-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z"/>
              </svg>
              <svg v-if="supporter.platform === 'x'" class="icon x-icon" viewBox="0 0 24 24" width="14" height="14">
                <path fill="currentColor" d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
              </svg>
            </a>
            <span v-else>{{ supporter.displayName }}</span>
          </div>
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

.supporter-group {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 12px;
  justify-content: flex-start;
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
}

.supporter-content {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  text-decoration: none;
  color: inherit;
}

.icon {
  display: inline-flex;
  align-items: center;
}

/* Colors for different tiers with hover states */
.golden-chef {
  background-color: rgba(255, 215, 0, 0.15);
  color: #B8860B;
}
.golden-chef.linked:hover {
  background-color: rgba(255, 215, 0, 0.25);
}
:root.dark .golden-chef {
  color: #FFD700;
}

.breakfast-club {
  background-color: rgba(192, 192, 192, 0.15);
  color: #808080;
}
.breakfast-club.linked:hover {
  background-color: rgba(192, 192, 192, 0.25);
}
:root.dark .breakfast-club {
  color: #E8E8E8;
}

.cereal-bowl {
  background-color: rgba(180, 95, 6, 0.15);
  color: #B4690E;
}
.cereal-bowl.linked:hover {
  background-color: rgba(180, 95, 6, 0.25);
}
:root.dark .cereal-bowl {
  color: #CD9B1D;
}

.choco-chip {
  background-color: rgba(64, 158, 255, 0.15);
  color: #1E90FF;
}
.choco-chip.linked:hover {
  background-color: rgba(64, 158, 255, 0.25);
}
:root.dark .choco-chip {
  color: #60A5FA;
}

/* Override default link hover behavior */
.supporter-content:hover {
  opacity: 1;
}

.pill:hover .supporter-content {
  color: inherit;
}

.error {
  color: var(--vp-c-danger);
}

.loading, .empty {
  color: var(--vp-c-text-2);
}
</style> 