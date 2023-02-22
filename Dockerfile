FROM ruby:3.2.1

WORKDIR /app
COPY . /app
RUN bundle install

EXPOSE 4567

CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
