FROM node:18-alpine

# Install dependencies
RUN apk add --no-cache curl

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --production

# Copy application code
COPY admin-token-validator.js ./
COPY admin-dashboard.html ./

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/api/admin/stats || exit 1

# Start application
CMD ["node", "admin-token-validator.js"]

