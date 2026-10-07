import "./styles/fonts.css";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/screens.css";

import { createPinia } from "pinia";
import { createApp } from "vue";

import App from "./App.vue";
import { createData } from "./api/client";
import { DATA_KEY, LOOKUPS_KEY } from "./console/data";
import { router } from "./router";
import { createLookups } from "./verify/lookups";

createApp(App).use(createPinia()).use(router).provide(DATA_KEY, createData()).provide(LOOKUPS_KEY, createLookups()).mount("#app");
