<template>
  <div class="exegol-history-import">
    <div class="import-container">
      <textarea
        v-model="historyContent"
        placeholder="Paste your Exegol history buffer here...

# Example:
# export VAR_NAME='value'
export ANOTHER_VAR='another_value'
export THIRD_VAR='third_value'
export FOURTH_VAR='fourth_value'
#export FIFTH_VAR='fifth_value'
"
        rows="8"
        class="import-textarea"
      ></textarea>
      <div class="import-actions">
        <button @click="clearTextarea" class="clear-button" :disabled="!historyContent">
          Clear
        </button>
        <button @click="parseAndImport" class="import-button" :disabled="!historyContent">
          Import Variables
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const historyContent = ref('')
const importResult = ref([])

// Count of successfully imported variables
const importedCount = computed(() => importResult.value.length)

// Function to parse the Exegol history content and extract variables
function parseAndImport() {
  if (!historyContent.value) return
  
  const lines = historyContent.value.split('\n')
  const extractedVars = []
  
  lines.forEach(line => {
    // Skip commented lines (starting with #)
    if (line.startsWith('#')) return
    
    // Match export statements: export VAR_NAME='value'
    const match = line.match(/export\s+([A-Z0-9_]+)=['"](.+)['"]/i)
    if (match && match.length === 3) {
      const name = match[1]
      const value = match[2]
      
      // Store extracted variable
      extractedVars.push({ name, value })
      
      // Save to localStorage using the same format as the variableCommands.ts plugin
      try {
        // Get existing variables from localStorage
        const storageKey = 'thr_commands_variables'
        const now = Date.now()
        
        // Load existing variables if any
        let existingData = {}
        const savedData = localStorage.getItem(storageKey)
        
        if (savedData) {
          const parsedData = JSON.parse(savedData)
          // Only use existing data if it hasn't expired
          if (parsedData.timestamp && parsedData.values) {
            existingData = parsedData.values
          }
        }
        
        // Update with new variable
        existingData[name] = value
        
        // Save back to localStorage with timestamp
        const dataToStore = {
          timestamp: now,
          values: existingData
        }
        
        localStorage.setItem(storageKey, JSON.stringify(dataToStore))
      } catch (e) {
        console.error('Failed to save variable:', e)
      }
    }
  })
  
  // Update the result display
  importResult.value = extractedVars
  
  // Trigger page refresh to apply variables (if any were imported)
  if (extractedVars.length > 0) {
    setTimeout(() => {
      window.location.reload()
    }, 500)
  }
}

function clearTextarea() {
  historyContent.value = ''
}

function clearResults() {
  importResult.value = []
}
</script>

<style scoped>
.exegol-history-import {
  margin: 1.5rem 0;
  font-family: var(--vp-font-family-base);
}

.import-container {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.import-textarea {
  width: 100%;
  padding: 0.75rem;
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background-color: var(--vp-c-bg-soft);
  resize: vertical;
}

.import-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
  width: 100%;
}

.import-button, .clear-button {
  padding: 0.5rem 1rem;
  font-size: 0.9rem;
  font-weight: 500;
  border-radius: 4px;
  border: 1px solid transparent;
  cursor: pointer;
  transition: background-color 0.2s, border-color 0.2s, color 0.2s;
}

.import-button {
  background-color: var(--vp-c-brand-2);
  color: var(--vp-c-white);
}

.import-button:hover {
  background-color: var(--vp-c-brand-3);
}

.import-button:disabled {
  background-color: var(--vp-c-gray);
  border-color: var(--vp-c-divider);
  color: var(--vp-c-text-3);
  cursor: not-allowed;
  opacity: 0.7;
}

.clear-button {
  background-color: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
  border-color: var(--vp-c-divider);
}

.clear-button:hover {
  background-color: var(--vp-c-bg-mute);
}

.clear-button:disabled {
  cursor: not-allowed;
  opacity: 0.7;
  color: var(--vp-c-text-3);
}

.import-result {
  margin-top: 1rem;
  padding: 1rem;
  border-radius: 6px;
  background-color: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
}

.result-heading {
  display: flex;
  justify-content: space-between;
  margin-bottom: 0.75rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

.clear-results {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 1.2rem;
  color: var(--vp-c-text-3);
  display: flex;
  align-items: center;
  padding: 0;
}

.clear-results:hover {
  color: var(--vp-c-text-2);
}

.result-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.result-item {
  display: flex;
  justify-content: space-between;
  padding: 0.4rem 0;
  border-bottom: 1px solid var(--vp-c-divider-light);
}

.result-item:last-child {
  border-bottom: none;
}

.variable-name {
  font-family: var(--vp-font-family-mono);
  color: var(--vp-c-brand);
  font-weight: 500;
}

.variable-value {
  font-family: var(--vp-font-family-mono);
  color: var(--vp-c-text-2);
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 60%;
  white-space: nowrap;
}
</style> 