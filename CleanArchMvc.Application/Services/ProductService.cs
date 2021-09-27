﻿using AutoMapper;
using CleanArchMvc.Application.DTOs;
using CleanArchMvc.Application.Interfaces;
using CleanArchMvc.Application.Products.Commands;
using CleanArchMvc.Application.Products.Queries;
using CleanArchMvc.Domain.Entities;
using CleanArchMvc.Domain.Interfaces;
using MediatR;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CleanArchMvc.Application.Services
{
    public class ProductService : IProductService
    {
        private readonly IMapper _mapper;
        private readonly IMediator _mediator;

        public ProductService(IMapper mapper, IMediator mediator)
        {
            _mapper = mapper;
            _mediator = mediator;
        }

        public async Task<IEnumerable<ProductDTO>> GetProducts()
        {
            var productsQuery = new GetProductsQuery();

            if (productsQuery == null)
                throw new Exception("Entity could not be loaded");

            var products = await _mediator.Send(productsQuery);
            return _mapper.Map<IEnumerable<ProductDTO>>(products);
        }

        public async Task<ProductDTO> GetById(int? id)
        {
            var productByIdQuery = new GetProductByIdQuery(id.Value);

            if (productByIdQuery == null)
                throw new Exception("Entity could not be loaded");

            var product = await _mediator.Send(productByIdQuery);
            return _mapper.Map<ProductDTO>(product);
        }

        public async Task Add(ProductDTO productDto)
        {
            var product = _mapper.Map<ProductCreateCommand>(productDto);
            await _mediator.Send(product);
        }

        public async Task Update(ProductDTO productDto)
        {
            var product = _mapper.Map<ProductUpdateCommand>(productDto);
            await _mediator.Send(product);
        }

        public async Task Remove(int? id)
        {
            var productRemoveCommand = new ProductRemoveCommand(id.Value);

            if (productRemoveCommand == null)
                throw new Exception("Entity could not be loaded");

            var product = await _mediator.Send(productRemoveCommand);
        }

    }
}