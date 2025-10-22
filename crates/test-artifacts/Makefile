all:
	for dir in programs/*/ ; do \
		echo "Building in $${dir}..."; \
		cd $${dir} && cargo prove build --build-target riscv64im-succinct-zkvm-elf || { echo "Failed at command: cd $${dir} && cargo prove build"; exit 1; }; \
		cd ../..; \
	done

.PHONY: all
