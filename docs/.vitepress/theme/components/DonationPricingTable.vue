<script setup lang="ts">
const tiers = [
  {
    emoji: '🍪',
    name: 'Choco Chip',
    price: '$any',
    period: 'one-time',
    description: 'Support us with a one-time donation with the amount of your choice 💖',
    stripeLink: 'https://buy.stripe.com/custom-one-time-link'
  },
  {
    emoji: '🥣',
    name: 'Cereal Bowl',
    price: '$20',
    period: 'per year',
    description: 'The Hacker Recipes needs you ❤️ If you like the project, please consider donating to keep it growing 🙏',
    stripeLink: 'https://buy.stripe.com/20-dollar-subscription'
  },
  {
    emoji: '👥',
    name: 'Breakfast Club',
    price: '$50',
    period: 'per year',
    description: 'For frequent users of The Hacker Recipes who want the project to deliver fresh content regularly 🫡',
    stripeLink: 'https://buy.stripe.com/50-dollar-subscription'
  },
  {
    emoji: '🧑‍🍳',
    name: 'Golden Chef',
    price: '$100',
    period: 'per year',
    description: 'Be one of the top supporters 🚀 You want the project to grow fast and provide new quality content soon.',
    stripeLink: 'https://buy.stripe.com/100-dollar-subscription'
  }
]
</script>

<template>
  <div class="pricing-container">
    <div class="pricing-grid">
      <div v-for="tier in tiers" :key="tier.name" class="pricing-card">
        <div class="card-content">
          <div class="card-header">
            <span class="emoji">{{ tier.emoji }}</span>
            <h3 class="tier-name">{{ tier.name }}</h3>
          </div>
          <div class="price-info">
            <span class="price">{{ tier.price }}</span>
            <span class="period">{{ tier.period }}</span>
          </div>
          <p class="description">{{ tier.description }}</p>
        </div>
        <a :href="tier.stripeLink" 
           class="donate-button" 
           target="_blank" 
           rel="noopener">
          Donate
        </a>
      </div>
    </div>
  </div>
</template>

<style scoped>
.pricing-container {
  margin: 2rem 0;
}

.pricing-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 1.5rem;
  margin: 0 auto;
}

.pricing-card {
  background-color: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  padding: 1.5rem;
  text-align: center;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  display: flex;
  flex-direction: column;
  min-height: 300px;
  align-items: center;
}

.card-header {
  margin-bottom: 1rem;
}

.emoji {
  font-size: 2.5rem;
  display: block;
  margin-bottom: 0.5rem;
}

.tier-name {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
  color: var(--vp-c-text-1);
}

.price-info {
  margin: 1rem 0;
}

.price {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--vp-c-brand);
}

.period {
  font-size: 0.9rem;
  color: var(--vp-c-text-2);
  margin-left: 0.25rem;
}

.description {
  color: var(--vp-c-text-2);
  margin: 1rem 0;
  font-size: 0.9rem;
  line-height: 1.5;
}

.donate-button {
  display: inline-block;
  background-color: var(--vp-c-brand-2);
  color: white;
  padding: 0.5rem 1.5rem;
  border-radius: 20px;
  text-decoration: none;
  font-weight: 500;
  transition: background-color 0.2s ease;
  margin-top: auto;
  width: fit-content;
}

.donate-button:hover {
  background-color: var(--vp-c-brand-3);
  color: white;
}

@media (max-width: 768px) {
  .pricing-grid {
    grid-template-columns: 1fr;
    gap: 1rem;
  }
}
</style> 