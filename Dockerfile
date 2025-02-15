# Use Node.js as the base image
FROM node:20-slim as builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy project files
COPY . .

# Build the VitePress site
RUN npm run docs:build

# Production image
FROM nginx:alpine

# Copy built files from builder
COPY --from=builder /app/docs/.vitepress/dist /usr/share/nginx/html

# Expose port 80
EXPOSE 80

# Default command
CMD ["nginx", "-g", "daemon off;"] 