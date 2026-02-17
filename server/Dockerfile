FROM node:20-bookworm

# Install nmap inside container
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

ENV PORT=8080
ENV SQLITE_STORAGE=/app/data/dev.sqlite

# Create data directory
RUN mkdir -p /app/data

EXPOSE 8080

CMD ["node", "src/server.js"]