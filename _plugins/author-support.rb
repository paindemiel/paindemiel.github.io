#!/usr/bin/env ruby
#
# Simple author support plugin for Jekyll with Chirpy theme
# Allows using 'author: author_name' in post front matter

module Jekyll
  # Add author information to posts
  Jekyll::Hooks.register :posts, :pre_render do |post, payload|
    # Get author key from front matter, default to 'p12miel'
    author_key = post.data['author'] || 'p12miel'
    
    # Load authors from _data/authors.yml
    authors = post.site.data['authors'] || {}
    
    # Get author info by key, fallback to default if not found
    author_info = authors[author_key] || authors['p12miel'] || {}
    
    # Merge with site defaults for backward compatibility
    site_author = {
      'name' => post.site.config['social']['name'],
      'email' => post.site.config['social']['email'],
      'avatar' => post.site.config['avatar'],
      'links' => post.site.config['social']['links']
    }
    
    # Merge author info with site defaults, author info takes precedence
    final_author = site_author.merge(author_info)
    
    # Add the author key for reference
    final_author['key'] = author_key
    
    # Add author info to post data
    post.data['author_info'] = final_author
  end

  # Add author information to pages
  Jekyll::Hooks.register :pages, :pre_render do |page, payload|
    # Only process pages that have author specified
    if page.data['author']
      author_key = page.data['author']
      author_info = AuthorSupport.get_author_info(page.site, author_key)
      page.data['author_info'] = author_info
      payload['site']['current_author'] = author_info
    end
  end
end 