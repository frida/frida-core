	.section .rodata, "a"
	.balign 16
	.globl frida_agent_image_start
frida_agent_image_start:
	.incbin FRIDA_AGENT_IMAGE
	.globl frida_agent_image_end
frida_agent_image_end:
