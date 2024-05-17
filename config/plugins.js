// ./config/plugins.js`
'use strict';

module.exports = {
  i18n: {
    enabled: true,
    defaultLocale: "ru", 
    locales: ["en", "ru", "uk"], 
  },
  'users-permissions': {
    enabled: true,
    config: {
      advancedSettings: {
        email_confirmation: false,
      },
      emailConfirmation: {
        enabled: true,
        i18n:{
          enabled: true
        }
      },
      resetPassword: {
        enabled: true,
      },
    },
  },
  email: {
    config: {
      provider: 'nodemailer',
      providerOptions: {
        host: 'smtp.gmail.com',
        port: 587, 
        auth: {
          user: process.env.MAILER_EMAIL || 'websiterequestx@gmail.com',
          pass: process.env.MAILER_PASSWORD || 'mujusltqkvgdsbjd',
        },
      },
      settings: {
        defaultFrom: 'hello@example.com', // Ваша за замовчуванням адреса відправника
        defaultReplyTo: 'hello@example.com', // Ваша адреса електронної пошти за замовчуванням для відповіді
      },
    },
  },
  
  'responsive-image': {
    breakpoints: [320, 640, 768, 1024, 1366, 1920], // Визначте необхідні розміри
    format: ['webp', 'jpeg'], // Виберіть формати для оптимізації
    quality: 70, // Встановіть якість зображення
    progressive: true, // Використовуйте прогресивне завантаження для JPEG
  },
  menus: {
    config: {
      layouts: {
        menuItem: { 
          link: [ 
            {
              input: {
                label: 'Title EN',
                name: 'title_en',
                type: 'text',
                placeholder: 'Английский перевод',
                required: true,
              },
              grid: {
                col: 12,
              },
            },
            {
              input: {
                label: 'Title UA',
                name: 'title_uk',
                type: 'text',
                placeholder: 'Украинский перевод',
                required: true,
              },
              grid: {
                col: 12,
              },
            },
          ],
        },
      },
    },
  }
};

