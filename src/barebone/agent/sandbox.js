Interceptor.attach(DebugSymbol.getFunctionByName('sandbox_create'), {
  onEnter() {
    console.log('>>> sandbox_create()');
  },
  onLeave() {
    console.log('<<< sandbox_create()');
  }
});
