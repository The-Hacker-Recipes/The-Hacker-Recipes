<template>
    <a
      class="donate"
      href="/contributing/donate"
    >
      <img width="22" height="22" src="/images/logo.svg" />
      <span>
        <p class="extra-info">Keep us growing</p>
        <p class="heading">Support THR</p>
        <p class="extra-info">Donate or buy merch!</p>
      </span>
    </a>
  </template>
  
  <style scoped>
  .donate {
    margin-top: 1rem;   
    margin-bottom: 1rem;
    border-radius: 14px;
    padding-left: 5px;
    padding-right: 5px;
    padding-top: 0.4rem;
    padding-bottom: 0.4rem;
    position: relative;
    font-size: 0.9rem;
    font-weight: 700;
    line-height: 1.1rem;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    gap: 1rem;
    background-color: var(--vp-c-bg-alt);
    border: 2px solid transparent; 
    transition: border-color 0.5s ease, box-shadow 0.1s ease, transform 0.3s ease;
    background-image: linear-gradient(var(--vp-c-bg-alt), var(--vp-c-bg-alt)), linear-gradient(120deg, #42aaff99, #7b42f699);
    background-origin: border-box;
    background-clip: padding-box, border-box;
  }

  .donate:hover {
    box-shadow: 0 0 2px #9e6eff80, 0 0 4px #66bbff80;
  }
  
  .donate img {
    transition: transform 0.5s ease;
    transform: scale(1.25);
  }
  .donate:hover img {
    transform: scale(1.75);
  }
  
  .donate .heading {
    color: var(--vp-c-text-1);
    transition: background-image 0.3s ease, color 0.3s ease;
    font-size: 1rem; 
  }
  
  .donate .extra-info {
    color: var(--vp-c-text-2);
    opacity: 0;
    font-size: 0.7rem;
    padding-left: 0.1rem;
    transition: opacity 0.5s ease;
  }
  .donate:hover .extra-info {
    opacity: 0.9;
  }
  </style>
  