<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { createClient } from '@supabase/supabase-js'

// Define types for our data
interface Supporter {
  name_or_link: string
}

// Initialize refs
const donaters = ref<Supporter[]>([])
const error = ref<string | null>(null)
const loading = ref(true)

// Initialize Supabase client
const supabase = createClient(
  'https://fvenaxmvigueigzjfkls.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZ2ZW5heG12aWd1ZWlnempma2xzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzE1MjgzNjcsImV4cCI6MjA0NzEwNDM2N30.rBWw75mH4NWNMM5ri-qNrCWSr3S_RHHnXoIxHbrRZ2c'
)

// Function to process links (Twitter/X and GitHub)
function processLink(link: string): string {
  console.log('Processing link:', link)
  
  if (link.includes('twitter.com') || link.includes('x.com')) {
    const username = link.split('/').pop() || ''
    return `<a href="${link}" target="_blank" rel="noopener">@${username}</a>`
  }
  
  if (link.includes('github.com')) {
    const username = link.split('/').pop() || ''
    return `<a href="${link}" target="_blank" rel="noopener">${username}</a>`
  }
  
  return link
}

// Function to fetch supporters from Supabase
async function getDonaters() {
  try {
    console.log('Fetching supporters from Supabase...')
    loading.value = true
    error.value = null

    const { data, error: supabaseError } = await supabase
      .from('supporters')
      .select('name_or_link')

    if (supabaseError) {
      throw supabaseError
    }

    console.log('Raw data from Supabase:', data)

    if (!data) {
      throw new Error('No data received from Supabase')
    }

    // Process the links
    donaters.value = data.map(supporter => ({
      name_or_link: processLink(supporter.name_or_link)
    }))

    console.log('Processed supporters:', donaters.value)
  } catch (e) {
    console.error('Error fetching supporters:', e)
    error.value = e instanceof Error ? e.message : 'An unknown error occurred'
  } finally {
    loading.value = false
  }
}

// Fetch data when component mounts
onMounted(() => {
  getDonaters()
})
</script>

<template>
  <div class="donaters">
    <p v-if="error" class="error">{{ error }}</p>
    <p v-else-if="loading" class="loading">Loading supporters...</p>
    <p v-else-if="donaters.length === 0" class="empty">No supporters found.</p>
    <p v-else v-html="donaters.map(d => d.name_or_link).join(', ')"></p>
  </div>
</template>

<style scoped>
.donaters {
  margin: 1rem 0;
}

.donaters p {
  line-height: 1.6;
  margin: 0;
}

.error {
  color: var(--vp-c-danger);
}

.loading, .empty {
  color: var(--vp-c-text-2);
}

:deep(a) {
  color: var(--vp-c-brand);
  text-decoration: none;
}

:deep(a:hover) {
  text-decoration: underline;
}
</style> 