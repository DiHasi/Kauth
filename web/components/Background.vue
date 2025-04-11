<template>
  <transition
      enter-active-class="transition duration-500 ease-out"
      enter-from-class="opacity-0 scale-0"
      enter-to-class="opacity-100 scale-100"
  >
    <div
        v-if="visible"
        class="bg-white bg-opacity-95 rounded-2xl drop-shadow-xl h-full dark:bg-gray-500"
    >
      <slot></slot>
    </div>
  </transition>
</template>

<script setup>
import { ref, onMounted } from 'vue';

const visible = ref(false);

onMounted(() => {
  setTimeout(() => {
    visible.value = true;
  }, 50); // небольшой "хак" чтобы Vue заметил переход
});
</script>
