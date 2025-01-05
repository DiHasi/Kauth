<script setup lang="ts">

</script>

<template>
  <div class="bg-white bg-opacity-95 rounded-2xl drop-shadow-xl flex
              flex-col p-6 w-full h-full justify-center items-center
              gap-6 *:w-1/4">
    <div class="text-center text-2xl">LOGIN</div>
    <div class="flex flex-row gap-3 items-center">
      <div class="flex flex-row items-center gap-1">
        <InputNumber inputId="integeronly" fluid />
        <InputNumber inputId="integeronly" fluid />
        <InputNumber inputId="integeronly" fluid />
      </div>
      <i class="pi pi-minus" style="color: #708090"></i>
      <div class="flex flex-row items-center gap-1">
        <InputNumber inputId="integeronly" fluid />
        <InputNumber inputId="integeronly" fluid />
        <InputNumber inputId="integeronly" fluid />
      </div>
    </div>
  </div>
</template>

<style scoped>

</style>