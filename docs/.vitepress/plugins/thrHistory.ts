import variableCommands from "vitepress-md-var";

// Storage key for persisting variables
const STORAGE_KEY = 'thr_commands_variables';
// 24 hours in milliseconds
const EXPIRY_TIME = 24 * 60 * 60 * 1000;

/**
 * Stores variable value to localStorage with expiration
 * @param varName - name of variable to store
 * @param varValue - value of variable to store
 */
function storeVar(varName, varValue) {
  const values = loadVarValues();
  try {
    values.set(varName, varValue);
    const dataToStore = {
      timestamp: Date.now(),
      values: Object.fromEntries(values)
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

export default function thrHistory(route) {
  // Initialize variable commands with the current route
  variableCommands(route, {
    loadVar: varName => loadVarValues().get(varName),
    storeVar: (varName, varValue) => storeVar(varName, varValue),
    styling: "thr",
  });

  // Watch for route changes to reinitialize variable commands
  if (route.onBeforeRouteUpdate) {
    route.onBeforeRouteUpdate((to) => {
      variableCommands(to, {
        loadVar: varName => loadVarValues().get(varName),
        storeVar: (varName, varValue) => storeVar(varName, varValue),
        styling: "thr",
      });
    });
  }
}