/// <reference types="vitest" />
import { defineConfig } from 'vite'
import dts from 'vite-plugin-dts'

export default defineConfig({
    test: {
        include: [
            'src/**/*.test.ts',
        ],
    },
    build: {
        lib: {
            entry: './src/index.ts',
            formats: ['es', 'cjs'],
            fileName: 'index',
        },
        minify: false,
        outDir: './dist',
        emptyOutDir: true,
    },
    plugins: [dts()]
})
