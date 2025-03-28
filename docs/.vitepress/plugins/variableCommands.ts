/**
 * VitePress plugin that enables interactive variable substitution in code blocks.
 * This plugin allows users to click on variables in code blocks and edit their values,
 * with the changes being reflected across all instances of that variable.
 */

/**
 * @file Variable Commands Plugin
 * @author Jun Rong "Junron" Lam
 * @author Charlie "Shutdown" Bromberg
 */


import { nextTick, onMounted, watch, onUpdated, onBeforeUpdate } from "vue";

// Storage key for persisting variables
const STORAGE_KEY = 'thr_commands_variables';
// 24 hours in milliseconds
const EXPIRY_TIME = 24 * 60 * 60 * 1000;

/**
 * Saves variable values to localStorage with expiration
 * @param varValues - Map of variable names and values to save
 */
function saveVarValues(varValues) {
  try {
    const dataToStore = {
      timestamp: Date.now(),
      values: Object.fromEntries(varValues)
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(dataToStore));
  } catch (e) {
    console.error('Failed to save variable values:', e);
  }
}

/**
 * Loads variable values from localStorage if not expired
 * @returns Map of variable names and their saved values
 */
function loadVarValues() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (!saved) return new Map();
    
    const data = JSON.parse(saved);
    const now = Date.now();
    
    // Check if data has expired (24 hours)
    if (data.timestamp && now - data.timestamp > EXPIRY_TIME) {
      // Data expired, remove it and return empty map
      localStorage.removeItem(STORAGE_KEY);
      return new Map();
    }
    
    // Data still valid
    return new Map(Object.entries(data.values || {}));
  } catch (e) {
    console.error('Failed to load variable values:', e);
    return new Map();
  }
}

/**
 * Processes an HTML element to replace variable placeholders with interactive spans and inputs.
 * @param elem - The HTML element to process
 * @param counters - Map to track the number of occurrences of each variable
 * @param varValues - Map to store the current values of variables
 */
function handleElement(elem, counters, varValues){
  // Replace all $variable patterns with interactive spans and hidden inputs
  elem.innerHTML = elem.innerHTML.replace(/\$(\w+)/g, (a, ...args) => {
    // Skip if the variable is at the start of the line (likely not a variable)
    if(args[1] == 0){
      return a;
    }
    // Skip common constants and special variables
    if(["$true", "$false", "$null"].includes(a.toLowerCase())){
      return a;
    }
    if(a.startsWith("$_")){
      return a;
    }
    if(a.startsWith("$no_md_var_")){
      return "$"+a.substring("$no_md_var_".length);
    }
    
    // Extract variable name and update counter
    a = a.substring(1);
    const count = (counters.get(a) || 0) + 1;
    counters.set(a, count);
    
    // Initialize variable value if not already set
    if (!varValues.has(a)) {
      varValues.set(a, "$" + a);
    }
    
    // Get the stored value (or default to the variable name)
    const displayValue = varValues.get(a);
    
    // Create interactive span and hidden input for the variable
    return (
      `<span class='md-var md-var-${a}' id='md-var-span-${a}-${count}'>${displayValue}</span>` +
      `<input class='md-var md-var-hidden md-var-${a}' id='md-var-input-${a}-${count}' autocomplete=off value=${displayValue}>`
    );
  });
}

/**
 * Finds all variables in code blocks and initializes their values
 * @returns Map containing variable names and their current values
 */
function findVarsInCode() {
  const counters = new Map();
  // Load saved values from localStorage
  const varValues = loadVarValues();

  // Process all code elements except those within VitePress documentation
  for(const elem of document.querySelectorAll(':not(.vp-doc) code')){
    handleElement(elem, counters, varValues);
  }

  return varValues;
}

/**
 * Refreshes the variable substitution UI and sets up event listeners
 */
const refreshVars = () => {
  const varValues = findVarsInCode();
  
  // Add styles for variable elements
  const inputStyle = document.createElement("style");
  inputStyle.innerHTML = `
    input.md-var-hidden {
      display: none;
    }
    span.md-var-hidden {
      visibility: hidden;
      white-space: pre;
      position: absolute;
    }
    html:not(.dark) span.md-var{
      color: #d01884 !important;
      border-bottom: 1px dashed #d01884;
    }
    html.dark span.md-var{
      color: #ff8bcb !important;
      border-bottom: 1px dashed #ff8bcb;
    }
    html:not(.dark) input.md-var {
      font: inherit;
      background: transparent;
      color: #d01884;
    }
    html.dark input.md-var {
      font: inherit;
      background: transparent;
      color: #ff8bcb;
    }
  `;
  document.head.appendChild(inputStyle);

  // Set up click handlers for variable spans
  document.querySelectorAll("span.md-var").forEach((element) => {
    element.addEventListener("click", () => {
      element.classList.add("md-var-hidden");
      const [_a, _b, _c, varName, idx] = element.id.split("-");
      const inputElement = document.getElementById(
        `md-var-input-${varName}-${idx}`
      )!! as HTMLInputElement;
      inputElement.classList.remove("md-var-hidden");
      inputElement.style.width =
        (element as HTMLSpanElement).offsetWidth + 5 + "px";
      inputElement.select();
    });
  });

  // Set up input handlers for variable inputs
  document.querySelectorAll("input.md-var").forEach((element) => {
    // Handle input changes
    element.addEventListener("input", () => {
      const inputElement = element as HTMLInputElement;
      const [_a, _b, _c, varName, idx] = element.id.split("-");
      const spanElement = document.getElementById(
        `md-var-span-${varName}-${idx}`
      )!!;
      varValues.set(varName, inputElement.value);
      // Update all instances of this variable
      document.querySelectorAll(`span.md-var-${varName}`).forEach((elem) => {
        const spanElem = elem as HTMLSpanElement;
        spanElem.innerText = inputElement.value;
      });
      inputElement.style.width =
        (spanElement as HTMLSpanElement).offsetWidth + 5 + "px";
      
      // Save updated values to localStorage
      saveVarValues(varValues);
    });

    // Handle focus loss
    element.addEventListener("focusout", () => {
      const inputElement = element as HTMLInputElement;
      const [_a, _b, _c, varName, idx] = element.id.split("-");
      const spanElement = document.getElementById(
        `md-var-span-${varName}-${idx}`
      )!!;
      inputElement.classList.add("md-var-hidden");
      spanElement.classList.remove("md-var-hidden");
      // Sync all input values for this variable
      document.querySelectorAll(`input.md-var-${varName}`).forEach((elem) => {
        const inputElem = elem as HTMLInputElement;
        inputElem.value = inputElement.value;
      });
    });
  });
}

/**
 * Main plugin function that initializes variable substitution
 * @param vitepressObj - VitePress instance object
 */
const variableCommands = (vitepressObj) => {
  const { route } = vitepressObj;
  // Initialize variables when component is mounted
  onMounted(() => {
    nextTick(refreshVars).catch();
  });
  // Refresh variables when route changes
  watch(() => route.data, () => {
    nextTick(refreshVars).catch();
  });
};

export default variableCommands;