FROM python:3.12.3

WORKDIR /trading

COPY requirements.txt requirements.txt
ARG TWINE_PASSWORD
RUN pip install --upgrade pip && \
    if [ -n "$TWINE_PASSWORD" ]; then \
      pip install --extra-index-url "https://nqa:$TWINE_PASSWORD@pkgs.dev.azure.com/nqartificial/286469a2-00b9-4c66-8d8a-879664a6826a/_packaging/desarrollo/pypi/simple/" package-nqa==0.8.11 && \
      pip install --extra-index-url "https://nqa:$TWINE_PASSWORD@pkgs.dev.azure.com/nqartificial/286469a2-00b9-4c66-8d8a-879664a6826a/_packaging/desarrollo/pypi/simple/" package-usage==0.2.8 && \
      pip install --extra-index-url "https://nqa:$TWINE_PASSWORD@pkgs.dev.azure.com/nqartificial/286469a2-00b9-4c66-8d8a-879664a6826a/_packaging/desarrollo/pypi/simple/" pnqa_15_scheduler==0.2.6 && \
      pip install --extra-index-url "https://nqa:$TWINE_PASSWORD@pkgs.dev.azure.com/nqartificial/286469a2-00b9-4c66-8d8a-879664a6826a/_packaging/desarrollo/pypi/simple/" pnqa_2_auth==0.3.9 && \
      pip install --extra-index-url "https://nqa:$TWINE_PASSWORD@pkgs.dev.azure.com/nqartificial/286469a2-00b9-4c66-8d8a-879664a6826a/_packaging/desarrollo/pypi/simple/" pnqa_14_usage==0.2.3 && \
      pip install --extra-index-url "https://nqa:$TWINE_PASSWORD@pkgs.dev.azure.com/nqartificial/286469a2-00b9-4c66-8d8a-879664a6826a/_packaging/desarrollo/pypi/simple/" pnqa_10_system==0.3.0 && \
      pip install --extra-index-url "https://nqa:$TWINE_PASSWORD@pkgs.dev.azure.com/nqartificial/286469a2-00b9-4c66-8d8a-879664a6826a/_packaging/desarrollo/pypi/simple/" pnqa_mailchimp==0.2.3 && \
      pip install --extra-index-url "https://nqa:$TWINE_PASSWORD@pkgs.dev.azure.com/nqartificial/286469a2-00b9-4c66-8d8a-879664a6826a/_packaging/desarrollo/pypi/simple/" whatsapp==0.4.16 && \
      pip install --extra-index-url "https://nqa:$TWINE_PASSWORD@pkgs.dev.azure.com/nqartificial/286469a2-00b9-4c66-8d8a-879664a6826a/_packaging/desarrollo/pypi/simple/" billing==0.3.3; \
    fi && \
    pip install -r requirements.txt --no-cache-dir

COPY . .

CMD ["uvicorn", "trading.main:app", "--host", "0.0.0.0", "--port", "8001"]