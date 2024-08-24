<template>
  <div class="centered-div">
    <div class="work-in-progress">Work in Progress</div>
  </div>
</template>

<script>
export default {
  name: 'WorkInProgress'
}
</script>

<style scoped>
.centered-div {
  display: flex;
  border: 1px solid #000000;
  border-radius: .25rem;
  justify-content: center;
  align-items: center;
  height: 20vh;
  background-color: #626262;
  color: #ffffff;
}

.work-in-progress {
  font-size: 24px;
  font-weight: bold;
  text-align: center;
}
</style>