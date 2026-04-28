# Upgrade to Node 22 Alpine (LTS) to support modern security patches
FROM node:22-alpine

# Install build tools for native modules (bcrypt/sqlite3)
RUN apk add --no-cache \
    python3 \
    make \
    g++

# Set the working directory
WORKDIR /app

# Copy dependency files first
COPY package*.json ./

# SECURITY FIX: Update npm to the latest version compatible with the environment
# We use --engine-strict=false as a safety net, but Node 22 handles this much better
RUN npm install -g npm@latest && npm install

# Copy the rest of the application code
COPY . .

# SECURITY: Set permissions for the non-root 'node' user
RUN chown -R node:node /app

# Switch to non-root user
USER node

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
