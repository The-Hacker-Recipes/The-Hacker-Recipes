<template>
    <div class="footer-links-container">
      <div class="footer-links">
        <a href="/policies/terms" class="footer-link">Terms</a>
        <a href="/policies/privacy" class="footer-link">Privacy</a>
        <a href="/policies/about" class="footer-link">About</a>
      </div>
    </div>
  </template>
  
  <style scoped>
.footer-links {
    display: flex;
    gap: 1.5rem;
    margin-bottom: 1rem;
  }
  
.footer-link {
    text-decoration: none;
    color: var(--vp-c-text-legal);
    font-size: 0.9rem;
  }

  @media (max-width: 960px) {
.footer-links-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    margin-top: 2rem;
    padding-top: 1rem;
    font-size: 0.9rem;
    width: 100%;
    }
    
.footer-links {
    display: flex;
    justify-content: center;
    gap: 1.5rem;
    margin-bottom: 1rem;
    }
    
.footer-link {
    text-decoration: none;
    color: var(--vp-c-text-legal);
    font-size: 0.9rem;
    }
}
  </style>
  