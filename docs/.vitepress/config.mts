import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Shared",
  description: "Helpful info",
  base: '/shared/',
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Flows', link: '/flows/' }
],

sidebar: {
  '/flows/': [
    {
      text: 'Flows',
      items: [
        { text: 'Overview', link: '/flows/' },
        { text: 'Legacy Users Flow', link: '/flows/legacyUsersFlow' }
      ]
    }
  ]
},

    socialLinks: [
      { icon: 'github', link: 'https://github.com/vuejs/vitepress' }
    ]
  }
})
