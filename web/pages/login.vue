<script setup lang="ts">
import {ref} from 'vue';
import {useRoute} from 'vue-router';

const route = useRoute();

// Переменные для формы
const username = ref<string>('');
const password = ref<string>('');
const scope = ref<string>(route.query.scope as string || '');
const state = ref<string>(route.query.state as string || '');
const redirect_uri = ref<string>(route.query.redirect_uri as string || '');
const client_name = ref<string>(route.query.client_name as string || '');

// Состояние ошибки
const errorMessage = ref<string>('');
const visible = ref<boolean>(false);
const domain = ref<string>('')

const showLogin = ref(false);


onMounted(() => {

  if (client_name.value != '') {
    domain.value = client_name.value
  } else {
    domain.value = getDomainFromUrl(redirect_uri.value);
  }
  
  useHead({
    title: `Login - ${domain.value}`
  });

  setTimeout(() => {
    showLogin.value = true;
  }, 50);
});

// Показываем сообщение об ошибке
const showError = (message: string) => {
  errorMessage.value = message;
  visible.value = true;

  setTimeout(() => {
    visible.value = false;
  }, 3500);
};

const getDomainFromUrl = (url: string): string => {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname;
  } catch (error) {
    console.error('Invalid URL:', error);
    return '';
  }
};

// Авторизация
const login = async () => {
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: username.value,
        password: password.value,
        scope: scope.value,
        state: state.value
      }),
    });

    if (!response.ok) {
      showError('Invalid credentials');
      return;
    }

    const data = await response.json();
    const domain = getDomainFromUrl(redirect_uri.value);

    if (!domain) {
      showError('Invalid redirect URL');
      return;
    }

    if (scope.value === "") {
      window.location.href = `${redirect_uri.value}`;
    }

    window.location.href = `${redirect_uri.value}?state=${state.value}&code=${data.code}`;

  } catch (error: any) {
    showError(error.message || 'An error occurred');
  }
};
</script>

<template>
  <!-- Сообщение об ошибке -->
  <div class="fixed top-4 left-1/2 transform -translate-x-1/2 z-50">
    <Message v-if="visible" severity="error" :life="3000">{{ errorMessage }}</Message>
  </div>

  <!-- Форма авторизации -->
  <transition
      enter-active-class="transition duration-500 ease-out"
      enter-from-class="opacity-0 scale-0"
      enter-to-class="opacity-100 scale-100"
  >
    <div
        v-if="showLogin"
        class="flex flex-col h-full *:w-full p-4 sm:p-0 *:sm:w-1/2 *:md:w-1/2 *:lg:w-1/4 justify-center items-center gap-6">
      <div class="text-center text-2xl">Login</div>
      <FloatLabel>
        <InputText id="username" v-model="username" class="w-full"/>
        <label for="username">Username</label>

      </FloatLabel>
      <FloatLabel class="*:w-full">
        <Password class="*:w-full" v-model="password" :feedback="false" inputId="password"/>
        <label class="w-full" for="password">Password</label>

      </FloatLabel>
      <Button label="Login" @click="login"/>
    </div>
  </transition>


</template>
