import forms from '@tailwindcss/forms';
import type { Config } from 'tailwindcss';

export default {
	content: ['./src/**/*.{html,js,svelte,ts}'],

	theme: {
		fontFamily: {
			'sans': ['Inter', 'Roboto', 'Helvetica Neue', 'Arial Nova', 'Nimbus Sans', 'Arial'],
		},
		extend: {}
	},

	plugins: [forms]
} as Config;
